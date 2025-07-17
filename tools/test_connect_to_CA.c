#include "connect_to_CA.h"
#include "gen_credentials.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>

#define ROOT_CERT_NAME "test_recv_root_cert.pem"
#define CERT_NAME "test_recv_cert.pem"

/* Please run CA program before running this one (CA needs to be listening to incoming connexions) */

int main()
{
    X509 *root_cert = NULL;
    X509 *cert = NULL;
    X509_REQ *CSR = NULL;
    EVP_PKEY *key = NULL;
    int ret = 0;

    // establish connection with CA. CA ip and port are hardcoded in connect_to_CA.h
    int sockfd = connect_to_CA();
    if (sockfd < 0)
    {
        fprintf(stderr, "Failure to connect to CA\n");
        return 1;
    }

    printf("Succesfully connected to CA %s:%d\n", CA_IP, CA_PORT);

    key = EVP_RSA_gen(256 * 8);
    CSR = gen_CSR(key, "XXX");
    if ((key == NULL) || (CSR == NULL))
    {
        fprintf(stderr, "Couldn't generate key or CSR.");
        ret = 1;
        goto end;
    }

    // function that implements the CSR protocol.
    if (send_CSR_wait_cert(sockfd, CSR, &root_cert, &cert) == 1)
    {
        fprintf(stderr, "Failed to request certificate from CA.\n");
        ret = 1;
        goto end;
    }

    // write the received certificates
    if (root_cert == NULL)
        printf("yes\n");

    if (write_cert(root_cert, ROOT_CERT_NAME) == 1)
    {
        fprintf(stderr, "Failed to write root certificate sent by CA.\n");
        ret = 1;
        goto end;
    }
    if (write_cert(cert, CERT_NAME) == 1)
    {
        fprintf(stderr, "Failed to write root certificate sent by CA.\n");
        ret = 1;
        goto end;
    }
    printf("Certificates successfully written in %s and %s.\n", ROOT_CERT_NAME, CERT_NAME);

end:
    X509_free(root_cert);
    X509_free(cert);
    X509_REQ_free(CSR);
    EVP_PKEY_free(key);
    close(sockfd);
    printf("Connexion closed.\n");
    return ret;
}