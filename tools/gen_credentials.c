#include "gen_credentials.h"

int write_key(EVP_PKEY *key, char *filename)
{
    /* instead of using encoder we could use openssl PEM library PEM_write_PKCS8PrivateKey()*/
    // create ctx for PEM encoder
    const char *format = "PEM";
    const char *structure = "PrivateKeyInfo";
    OSSL_ENCODER_CTX *ectx = OSSL_ENCODER_CTX_new_for_pkey(key, EVP_PKEY_KEYPAIR, format, structure, NULL);
    if (ectx == NULL)
    {
        fprintf(stderr, "Couldn't create PEM encoder.\n");
        return 1;
    }

    // write in a file
    FILE *fd = fopen(filename, "w");
    if (fd == 0)
    {
        perror("Couldn't open file");
        OSSL_ENCODER_CTX_free(ectx);
        return 1;
    }

    if (OSSL_ENCODER_to_fp(ectx, fd) == 0)
    {
        fprintf(stderr, "Couldn't write key in %s.\n", filename);
        fclose(fd);
        OSSL_ENCODER_CTX_free(ectx);

        // if writing fails, let's delete the empty file.
        if (remove(filename) != 0)
        {
            perror("Couldn't delete file");
            return 1;
        }

        return 1;
    }

    // read-only permission
    if (chmod(filename, 0440) != 0)
    {
        fclose(fd);
        OSSL_ENCODER_CTX_free(ectx);
        perror("Couldn't change permissions of keyfile to read-only");
        return 1;
    }

    fclose(fd);
    OSSL_ENCODER_CTX_free(ectx);
    return 0;
}

int gen_keyfile(char *filename)
{
    EVP_PKEY *key = EVP_RSA_gen(256 * 8);
    if (key == NULL)
    {
        fprintf(stderr, "Couldn't generate RSA key.");
        return 1;
    }

    if (write_key(key, filename) == 1)
    {
        fprintf(stderr, "Couldn't write RSA key in %s.", filename);
        EVP_PKEY_free(key);
        return 1;
    }

    EVP_PKEY_free(key);
    return 0;
}

EVP_PKEY *read_key(char *filename)
{
    FILE *fd = NULL;
    EVP_PKEY *key = NULL;

    fd = fopen(filename, "r");
    if (fd == 0)
    {
        perror("Couldn't open file");
        return NULL;
    }

    key = PEM_read_PrivateKey(fd, NULL, NULL, NULL);
    if (key == NULL)
    {
        fprintf(stderr, "Couldn't read key %s\n.", filename);
        fclose(fd);
        return NULL;
    }

    fclose(fd);
    return key;
}

// TODO for the moment we can only add the Common Name (mandatory), but typically this can include
// more information on the user (optionally).

X509_NAME *make_subject_name(const unsigned char *user_CN)
{
    X509_NAME *subj_name = NULL;

    subj_name = X509_NAME_new();
    if (subj_name == NULL)
    {
        fprintf(stderr, "Allocation of X509_NAME failed.\n");
        return NULL;
    }

    // add Common Name
    if (X509_NAME_add_entry_by_txt(subj_name, "CN", MBSTRING_ASC, user_CN, -1, -1, 0) == 0)
    {
        fprintf(stderr, "Couldn't add CN.\n");
        X509_NAME_free(subj_name);
        return NULL;
    }

    return subj_name;
}

int write_cert(X509 *cert, char *filename)
{
    FILE *fd;
    int ret = 0;

    fd = fopen(filename, "w");
    if (fd == 0)
    {
        perror("Couldn't open file");
        return 1;
    }

    if (!PEM_write_X509(fd, cert))
    {
        fprintf(stderr, "Couldn't write certificate in file %s.\n", filename);
        ret = 1;

        // if writing fails, let's delete the empty file.
        if (remove(filename) != 0)
        {
            perror("Couldn't delete file");
        }
        goto end;
    }

end:
    fclose(fd);
    return ret;
}

X509 *gen_cert(EVP_PKEY *user_key, EVP_PKEY *root_key, X509_NAME *user_name, X509_NAME *issuer_name)
{
    X509 *cert = NULL;
    ASN1_INTEGER *serialnb = NULL;
    ASN1_TIME *notBefore = NULL;
    ASN1_TIME *notAfter = NULL;
    int ret = 0;

    cert = X509_new();
    if (cert == NULL)
    {
        char buf[256];
        ERR_error_string_n(ERR_get_error(), buf, sizeof(buf)); // check openssl error queue
        fprintf(stderr, "Couldn't create certificate: %s.\n", buf);
        return NULL;
    }

    // set issuer and subject name
    if (X509_set_subject_name(cert, user_name) == 0)
    {
        fprintf(stderr, "Couldn't set subject name.\n");
        ret = 1;
        goto end;
    }

    if (X509_set_issuer_name(cert, issuer_name) == 0)
    {
        fprintf(stderr, "Couldn't set issuer name.\n");
        ret = 1;
        goto end;
    }

    // serial number
    serialnb = ASN1_INTEGER_new();
    if (ASN1_INTEGER_set(serialnb, 3) == 0) // TODO I put 3 as serial number
    {
        fprintf(stderr, "Allocation of ASN1_INTEGER (serial number) failed.\n");
        ret = 1;
        goto end;
    }
    if (X509_set_serialNumber(cert, serialnb) == 0)
    {
        fprintf(stderr, "Couldn't set serial number.\n");
        ret = 1;
        goto end;
    }

    // not before/after time
    notBefore = ASN1_TIME_new();
    notAfter = ASN1_TIME_new();
    if (X509_gmtime_adj(notBefore, 0) == NULL)
    {
        fprintf(stderr, "Allocation of ASN1_TIME (\"Not Before\") failed.\n");
        ret = 1;
        goto end;
    }
    if (X509_gmtime_adj(notAfter, (long)60 * 60 * 24 * 365) == 0)
    {
        fprintf(stderr, "Allocation of ASN1_TIME (\"Not After\") failed.\n");
        ret = 1;
        goto end;
    }
    if (X509_set1_notBefore(cert, notBefore) == 0)
    {
        fprintf(stderr, "Couldn't set \"Not After\".\n");
        ret = 1;
        goto end;
    }
    if (X509_set1_notAfter(cert, notAfter) == 0)
    {
        fprintf(stderr, "Couldn't set \"Not After\".\n");
        ret = 1;
        goto end;
    }

    // set certificate public key

    if (X509_set_pubkey(cert, user_key) == 0)
    {
        fprintf(stderr, "Couldn't set public key.\n");
        ret = 1;
        goto end;
    }

    // sign certificate
    if (X509_sign(cert, root_key, NULL) == 0)
    {
        fprintf(stderr, "Couldn't sign certificate.\n");
        ret = 1;
        goto end;
    }

end:
    ASN1_TIME_free(notBefore);
    ASN1_TIME_free(notAfter);
    ASN1_INTEGER_free(serialnb);
    if (ret == 1)
    {
        X509_free(cert);
        return NULL;
    }
    return cert;
}

int gen_cert_file(char *filename, EVP_PKEY *user_key, EVP_PKEY *root_key, X509_NAME *user_name, X509_NAME *issuer_name)
{
    X509 *cert = gen_cert(user_key, root_key, user_name, issuer_name);
    if (cert == NULL)
    {
        fprintf(stderr, "Error generating certificate %s", filename);
        return 1;
    }

    if (write_cert(cert, filename) == 1)
    {
        fprintf(stderr, "Error writing certificate %s", filename);
        X509_free(cert);
        return 1;
    }

    X509_free(cert);
    return 0;
}

X509 *read_cert(char *filename)
{
    FILE *fd = NULL;
    X509 *cert = NULL;

    fd = fopen(filename, "r");
    if (fd == 0)
    {
        perror("Couldn't open file");
        return NULL;
    }

    cert = PEM_read_X509(fd, NULL, NULL, NULL);
    if (cert == NULL)
    {
        fprintf(stderr, "Couldn't read cert %s\n.", filename);
        fclose(fd);
        return NULL;
    }

    fclose(fd);
    return cert;
}

X509_REQ *gen_CSR(EVP_PKEY *key, const unsigned char *CN)
{
    X509_REQ *CSR = NULL;
    X509_NAME *subject_name = NULL;
    int ret = 0;

    CSR = X509_REQ_new();
    if (CSR == NULL)
    {
        fprintf(stderr, "Allocation of X509_REQ failed.\n");
        return NULL;
    }

    // set public key
    if (X509_REQ_set_pubkey(CSR, key) == 0)
    {
        fprintf(stderr, "Failed to set public key.\n");
        ret = 1;
        goto end;
    }

    // set CN
    subject_name = X509_NAME_new();
    if (subject_name == NULL)
    {
        fprintf(stderr, "Allocation of X509_NAME failed.\n");
        ret = 1;
        goto end;
    }

    if (X509_NAME_add_entry_by_txt(subject_name, "CN", MBSTRING_ASC, CN, -1, -1, 0) == 0)
    {
        fprintf(stderr, "Couldn't create CN.\n");
        ret = 1;
        goto end;
    }

    if (X509_REQ_set_subject_name(CSR, subject_name) == 0)
    {
        fprintf(stderr, "Set X509_REQ subject name failed.\n");
        ret = 1;
        goto end;
    }

    // sign CSR
    if (X509_REQ_sign(CSR, key, NULL) == 0)
    {
        fprintf(stderr, "Couldn't sign CSR.\n");
        ret = 1;
        goto end;
    }

end:
    X509_NAME_free(subject_name);
    if (ret == 1)
    {
        X509_REQ_free(CSR);
        return NULL;
    }
    return CSR;
}

int write_CSR(X509_REQ *CSR, char *filename)
{
    FILE *fd;
    int ret = 0;

    fd = fopen(filename, "w");
    if (fd == 0)
    {
        perror("Couldn't open file");
        return 1;
    }

    if (!PEM_write_X509_REQ(fd, CSR))
    {
        fprintf(stderr, "Couldn't write CSR in file %s.\n", filename);
        ret = 1;

        // if writing fails, let's delete the empty file.
        if (remove(filename) != 0)
        {
            perror("Couldn't delete file");
        }
        goto end;
    }

end:
    fclose(fd);
    return ret;
}

int gen_CSR_file(EVP_PKEY *key, const unsigned char *CN, char *filename)
{
    X509_REQ *CSR = gen_CSR(key, CN);
    if (CSR == NULL)
    {
        fprintf(stderr, "Error generating CSR %s", filename);
        return 1;
    }

    if (write_CSR(CSR, filename) == 1)
    {
        fprintf(stderr, "Error writing CSR in file %s", filename);
        X509_REQ_free(CSR);
        return 1;
    }

    X509_REQ_free(CSR);
    return 0;
}

X509_REQ *read_CSR(char *filename)
{
    X509_REQ *CSR = NULL;
    FILE *fd = NULL;

    fd = fopen(filename, "r");
    if (fd == 0)
    {
        perror("Couldn't open file");
        return NULL;
    }

    CSR = PEM_read_X509_REQ(fd, NULL, NULL, NULL);
    if (CSR == NULL)
    {
        fprintf(stderr, "Couldn't read key %s\n.", filename);
        fclose(fd);
        return NULL;
    }

    fclose(fd);
    return CSR;
}

X509 *gen_cert_from_CSR(X509_REQ *CSR, EVP_PKEY *root_key, X509_NAME *issuer_name)
{
    EVP_PKEY *pub_key = NULL;
    X509_NAME *subj_name = NULL;
    X509 *cert = NULL;

    pub_key = X509_REQ_get_pubkey(CSR);
    if (pub_key == NULL)
    {
        fprintf(stderr, "Couldn't extract public key from CSR.\n");
        goto end;
    }

    // (note: X509_REQ_check_private_key() verifies if the public key in the CSR
    // matches with a given private key)

    // Verify the signature of the certificate.
    // If the signature is incorrect, we don't generate a certificate.
    int res = X509_REQ_verify(CSR, pub_key);
    if (res == 0)
    {
        fprintf(stderr, "Incorrect CSR signature.\n");
        goto end;
    }
    else if (res < 0)
    {
        fprintf(stderr, "Invalid CSR signature or malformed CSR.\n");
        goto end;
    }

    printf("checked CSR: CSR signature is valid.\n");

    // Now that we have confirmed that the CSR is correctly signed, we can proceed to generate the certificate.

    subj_name = X509_REQ_get_subject_name(CSR); // don't free subj_name!
    if (subj_name == NULL)
    {
        fprintf(stderr, "Coudln't extract subject name from CSR.\n");
        goto end;
    }

    cert = gen_cert(pub_key, root_key, subj_name, issuer_name);
    if (cert == NULL)
    {
        fprintf(stderr, "Certificate Generation failed.\n");
        goto end;
    }

end:
    EVP_PKEY_free(pub_key);
    return cert;
}
