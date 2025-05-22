#include "gen_credentials.h"

/* TEST functions of gen_credentials.c : create, read, write private key ; create TLS certificate */
int main()
{
    EVP_PKEY *key = NULL;
    X509_NAME *user_name = NULL;
    int ret = 0;

    if (gen_keyfile("test_key.pem") == 1)
    {
        fprintf(stderr, "read key err\n");
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

    user_name = make_subject_name("XXX");
    if (user_name == NULL)
    {
        fprintf(stderr, "make certificate name err\n");
        ret = 1;
        goto end;
    }
    
    if (gen_cert("test_cert.pem", key, key, user_name, user_name) == 1) // self-sign certificate
    {
        fprintf(stderr, "gen cert err\n");
        ret = 1;
        goto end;
    }

    printf("test_cert.pem generated.\n");

    if (gen_CSR_file(key, "XXX", "test_CSR.pem") == 1)
    {
        fprintf(stderr, "gen CSR err\n");
        ret = 1;
        goto end;
    }

    printf("test_CSR.pem generated.\n");

end:
    X509_NAME_free(user_name);
    EVP_PKEY_free(key);
    return ret;
}