#include "gen_credentials.h"

/* TEST functions of gen_credentials.c : create, read, write private key ; create TLS certificate */
int main()
{
    if (gen_keyfile("test_key.pem") == 1)
    {
        fprintf(stderr, "read key err\n");
        return 1;
    }

    EVP_PKEY *key = read_key("test_key.pem");
    if (key == NULL)
    {
        fprintf(stderr, "read key err\n");
        return 1;
    }

    if (gen_cert("test_cert.pem", key) == 1)
    {
        fprintf(stderr, "gen cert err\n");
        return 1;
    }

    EVP_PKEY_free(key);
    return 0;
}