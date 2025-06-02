#include "serialization.h"

int encode_CSR_to_buf(X509_REQ *CSR, char *buf)
{
    BIO *bio = NULL;
    int ret = 0;

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
    {
        fprintf(stderr, "Error BIO allocation.\n");
        return 1;
    }

    // write CSR to bio
    if (!PEM_write_bio_X509_REQ(bio, CSR))
    {
        fprintf(stderr, "Error writing CSR to bio.\n");
        ret = 1;
        goto end;
    }

    // use bio to convert to a buffer
    size_t pem_len = BIO_pending(bio);
    // printf("buffer size needed for CSR: %ld\n",pem_len);
    int res = BIO_read(bio, buf, pem_len);
    if (res == -2)
    {
        fprintf(stderr, "Error reading data from bio: this type of bio can't perform this operation.\n");
        ret = 1;
        goto end;
    }
    else if (res < 0)
    {
        fprintf(stderr, "Couldn't write CSR from bio to buffer.\n");
        ret = 1;
        goto end;
    }

end:
    BIO_free(bio);
    return ret;
}

X509 *decode_cert_from_buf(char *PEM_cert)
{
    BIO *bio = NULL;
    X509 *cert = NULL;

    // write from raw data to a bio
    bio = BIO_new_mem_buf(PEM_cert, -1);
    if (bio == NULL)
    {
        fprintf(stderr, "Error writing PEM cert to BIO.\n");
        return NULL;
    }

    // read from bio to convert to X509 object
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (cert == NULL)
    {
        fprintf(stderr, "Err reading certificate from BIO.\n");
        goto end;
    }

end:
    BIO_free(bio);
    return cert;
}

X509_REQ *decode_CSR_from_buf(char *PEM_CSR)
{
    BIO *bio = NULL;
    X509_REQ *CSR = NULL;

    // write from raw data to a bio
    bio = BIO_new_mem_buf(PEM_CSR, -1);
    if (bio == NULL)
    {
        fprintf(stderr, "Error writing PEM CSR to BIO.\n");
        return NULL;
    }

    // read from bio to convert to X509_REQ object
    CSR = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    if (CSR == NULL)
    {
        fprintf(stderr, "Err reading CSR from BIO.\n");
        goto end;
    }

end:
    BIO_free(bio);
    return CSR;
}

int encode_CERT_to_buf(X509 *cert, char *buf)
{
    BIO *bio = NULL;
    int ret = 0;

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
    {
        fprintf(stderr, "Error BIO allocation.\n");
        return 1;
    }

    if (!PEM_write_bio_X509(bio, cert))
    {
        fprintf(stderr, "Error writing cert to bio.\n");
        ret = 1;
        goto end;
    }

    size_t pem_len = BIO_pending(bio);
    int res = BIO_read(bio, buf, pem_len);
    if (res == -2)
    {
        fprintf(stderr, "Error reading data from bio: this type of bio can't perform this operation.\n");
        ret = 1;
        goto end;
    }
    else if (res < 0)
    {
        fprintf(stderr, "Couldn't write cert from bio to buffer.\n");
        ret = 1;
        goto end;
    }

end:
    BIO_free(bio);
    return ret;
}

int is_csr(char *buf)
{
    if (strstr(buf, "-----BEGIN CERTIFICATE REQUEST-----") == NULL)
    {
        return 0;
    }
    return 1;
}

int is_tls_certificate(char *buf)
{
    if (strstr(buf, "-----BEGIN CERTIFICATE-----") == NULL)
    {
        return 0;
    }
    return 1;
}