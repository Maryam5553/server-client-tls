#include "gen_credentials.h"

// Write key pair in the file given in parameter (creating the file if necessary)
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
        return 1;
    }

    fclose(fd);
    OSSL_ENCODER_CTX_free(ectx);
    return 0;
}

// Generate a 256 bytes RSA key, and write it in the file given in parameter.
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

// Read the key in the file given in parameter.
// No need to allocate EVP_PKEY (with EVP_PKEY_new), but after this function
// you need to free the key with EVP_PKEY_free (only in case of success).
// Returns NULL if didn't work.
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

    key = EVP_PKEY_new();
    if (key == NULL)
    {
        fprintf(stderr, "Allocation of EVP_PKEY failed.\n");
        fclose(fd);
        return NULL;
    }

    if (PEM_read_PrivateKey(fd, &key, NULL, NULL) == NULL)
    {
        fprintf(stderr, "Couldn't read key %s\n.", filename);
        EVP_PKEY_free(key);
        fclose(fd);
        return NULL;
    }

    fclose(fd);
    return key;
}

// Generate a TLS certificate, using the key given in parameter
int gen_cert(char *filename, EVP_PKEY *pkey)
{
    X509 *cert = NULL;
    X509_NAME *name = NULL;
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
        ret = 1;
        goto end;
    }

    // set issuer and subject name
    name = X509_NAME_new();
    if (name == NULL)
    {
        fprintf(stderr, "Allocation of X509_NAME failed.\n");
        ret = 1;
        goto end;
    }
    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"XXX", -1, -1, 0) == 0)
    {
        fprintf(stderr, "Couldn't create CN.\n");
        ret = 1;
        goto end;
    }
    if (X509_set_subject_name(cert, name) == 0)
    {
        fprintf(stderr, "Couldn't set subject name.\n");
        ret = 1;
        goto end;
    }
    if (X509_set_issuer_name(cert, name) == 0)
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

    // set public key

    if (X509_set_pubkey(cert, pkey) == 0)
    {
        fprintf(stderr, "Couldn't set public key.\n");
        ret = 1;
        goto end;
    }

    // sign certificate
    if (X509_sign(cert, pkey, NULL) == 0)
    {
        fprintf(stderr, "Couldn't sign certificate.\n");
        ret = 1;
        goto end;
    }

    // WRITE CERTIFICATE

    FILE *fd = fopen(filename, "w");
    if (fd == 0)
    {
        perror("Couldn't open file");
        return 1;
    }

    if (!PEM_write_X509(fd, cert))
    {
        fprintf(stderr, "Couldn't write certificate in file %s.\n", filename);
        X509_free(cert);
        return 1;
    }

end:
    ASN1_TIME_free(notBefore);
    ASN1_TIME_free(notAfter);
    ASN1_INTEGER_free(serialnb);
    X509_NAME_free(name);
    X509_free(cert);

    fclose(fd);
    return ret;
}
