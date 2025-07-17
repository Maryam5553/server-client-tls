#include "request_TLS_certificate.h"

int request_TLS_certificate(EVP_PKEY *private_key, const unsigned char *CN, char *root_cert_filename, char *TLS_cert_filename)
{
    X509 *root_cert = NULL;
    X509 *cert = NULL;
    X509_REQ *CSR = NULL;
    int ret = 0;

    int sockfd = connect_to_CA();
    if (sockfd < 0)
    {
        fprintf(stderr, "Failure to connect to CA\n");
        return 1;
    }

    printf("Succesfully connected to CA %s:%d\n", CA_IP, CA_PORT);

    CSR = gen_CSR(private_key, CN);
    if (CSR == NULL)
    {
        fprintf(stderr, "Couldn't generate CSR.");
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
    if (write_cert(root_cert, root_cert_filename )== 1)
    {
        fprintf(stderr, "Failed to write root certificate sent by CA.\n");
        ret = 1;
        goto end;
    }
    if (write_cert(cert, TLS_cert_filename) == 1)
    {
        fprintf(stderr, "Failed to write root certificate sent by CA.\n");
        ret = 1;
        goto end;
    }
    printf("Certificates successfully written in %s and %s.\n", root_cert_filename, TLS_cert_filename);

end:
    X509_free(root_cert);
    X509_free(cert);
    X509_REQ_free(CSR);
    close(sockfd);
    printf("Connexion closed.\n");
    return ret;
}