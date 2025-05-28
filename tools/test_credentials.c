#include "gen_credentials.h"

/* TEST functions of gen_credentials.c (manipulation of keys/TLS certificate/CSR) */

int main()
{
    EVP_PKEY *key = NULL;
    X509_NAME *user_name = NULL;
    X509 *cert = NULL;
    X509 *cert2 = NULL;
    X509 *cert3 = NULL;
    X509_REQ *CSR = NULL;
    X509_REQ *CSR2 = NULL;
    int ret = 0;

    // KEY
    if (gen_keyfile("test_key.pem") == 1)
    {
        fprintf(stderr, "gen keyfile err\n");
        ret = 1;
        goto end;
    }

    printf("test_key.pem generated.\n");

    key = read_key("test_key.pem");
    if (key == NULL)
    {
        fprintf(stderr, "read key err\n");
        ret = 1;
        goto end;
    }

    printf("Successfully read test_key.pem.\n");

    if (write_key(key, "test_key2.pem") == 1)
    {
        fprintf(stderr, "write key err\n");
        ret = 1;
        goto end;
    }

    printf("Key written in test_key2.pem.\n");

    // CERT
    user_name = make_subject_name("XXX");
    if (user_name == NULL)
    {
        fprintf(stderr, "make certificate name err\n");
        ret = 1;
        goto end;
    }

    cert = gen_cert(key, key, user_name, user_name);
    if (cert == NULL) // self-sign certificate
    {
        fprintf(stderr, "gen cert err\n");
        ret = 1;
        goto end;
    }

    printf("TLS certificate generated.\n");

    if (gen_cert_file("test_cert.pem", key, key, user_name, user_name) == 1)
    {
        fprintf(stderr, "gen cert file err\n");
        ret = 1;
        goto end;
    }

    printf("Certificate generated and written in test_cert.pem.\n");

    cert2 = read_cert("test_cert.pem");
    if (cert2 == NULL)
    {
        fprintf(stderr, "read cert err\n");
        ret = 1;
        goto end;
    }

    printf("Successfully read test_cert.pem.\n");

    if (write_cert(cert2, "test_cert2.pem") == 1)
    {

        fprintf(stderr, "write cert err\n");
        ret = 1;
        goto end;
    }
    printf("Wrote certificate in test_cert2.pem.\n");

    // CSR
    CSR = gen_CSR(key, "XXX");
    if (CSR == NULL)
    {
        fprintf(stderr, "gen CSR err\n");
        ret = 1;
        goto end;
    }

    printf("CSR generated.\n");

    if (gen_CSR_file(key, "XXX", "test_CSR.pem") == 1)
    {
        fprintf(stderr, "gen CSR err\n");
        ret = 1;
        goto end;
    }

    printf("CSR generated and written in test_CSR.pem.\n");

    CSR2 = read_CSR("test_CSR.pem");
    if (CSR2 == NULL)
    {
        fprintf(stderr, "read CSR err\n");
        ret = 1;
        goto end;
    }

    printf("Successfully read test_CSR.pem.\n");

    if (write_CSR(CSR2, "CSR2.pem") == 1)
    {
        fprintf(stderr, "write CSR err\n");
        ret = 1;
        goto end;
    }

    printf("Wrote CSR in test_CSR2.pem.\n");

    cert3 = gen_cert_from_CSR(CSR, key, user_name);
    if (cert3 == NULL)
    {
        fprintf(stderr, "gen cert from CSR err\n");
        ret = 1;
        goto end;
    }

    printf("TLS certificate generated from CSR.\n");

    char buf[2048] = {0};
    if (encode_CSR_to_buf(CSR, buf) == 1)
    {
        fprintf(stderr, "encode CSR to buf didn't work\n");
        ret = 1;
        goto end;
    }

    printf("CSR was sucessfully read to buffer:\n%s", buf);

end:
    EVP_PKEY_free(key);
    X509_NAME_free(user_name);
    X509_free(cert);
    X509_free(cert2);
    X509_free(cert3);
    X509_REQ_free(CSR);
    X509_REQ_free(CSR2);
    return ret;
}