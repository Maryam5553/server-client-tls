#include "gen_credentials.h"

/* TEST functions of gen_credentials.c : create, read, write private key ; create TLS certificate */
int main()
{
    if (gen_keyfile("test_key.pem") == 1)
    {
        fprintf(stderr, "read key err\n");
        return 1;
    }

    printf("test_key.pem generated.\n");

    EVP_PKEY *key = read_key("test_key.pem");
    if (key == NULL)
    {
        fprintf(stderr, "read key err\n");
        return 1;
    }

    printf("Successfully read test_key.pem.\n");

    if (gen_cert("test_cert.pem", key, key, "XXX", "XXX") == 1) // self-sign certificate
    {
        fprintf(stderr, "gen cert err\n");
        return 1;
    }

    printf("test_cert.pem generated.\n");

    if (gen_CSR_file(key, "XXX", "test_CSR.pem") == 1)
    {
        fprintf(stderr, "gen CSR err\n");
        return 1;
    }

    printf("test_CSR.pem generated.\n");

    EVP_PKEY_free(key);
    return 0;
}