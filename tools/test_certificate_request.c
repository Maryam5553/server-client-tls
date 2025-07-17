#include "request_TLS_certificate.h"
#include <openssl/rsa.h>

/* Please run CA program before running this one (CA needs to be listening to incoming connexions) */

int main()
{
    EVP_PKEY *key = NULL;
    char *ROOT_CERT_NAME = "test_recv_root_cert.pem";
    char *CERT_NAME = "test_recv_cert.pem";
    char *CN = "XXX";

    key = EVP_RSA_gen(256 * 8);
    if (key == NULL)
    {
        fprintf(stderr, "Couldn't generate private key.");
        return 1;
    }

    if (request_TLS_certificate(key, CN, ROOT_CERT_NAME, CERT_NAME) == 1)
    {
        fprintf(stderr, "Error: certicate request failed.");
        EVP_PKEY_free(key);
        return 1;
    }

    EVP_PKEY_free(key);
    return 0;
}