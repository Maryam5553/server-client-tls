#include "request_TLS_certificate.h"

int request_TLS_certificate(char *keyfile_name, const unsigned char *CN, char *root_cert_filename, char *TLS_cert_filename)
{
    X509 *root_cert = NULL;
    X509 *cert = NULL;
    EVP_PKEY *priv_key = NULL;
    X509_REQ *CSR = NULL;
    int sockfd = 0;
    int ret = 0;

    // generate a CSR
    priv_key = read_key(keyfile_name);
    if (priv_key == NULL)
    {
        fprintf(stderr, "Couldn't read private key from %s.\n", keyfile_name);
        ret = 1;
        goto end;
    }

    CSR = gen_CSR(priv_key, CN);
    if (CSR == NULL)
    {
        fprintf(stderr, "Couldn't generate CSR.\n");
        ret = 1;
        goto end;
    }
    printf("CSR generated using private key %s.\n", keyfile_name); // TODO print CSR

    // establish a connexion to the Certification Authority
    sockfd = connect_to_CA();
    if (sockfd < 0)
    {
        fprintf(stderr, "Failure to connect to CA\n");
        ret = 1;
        goto end;
    }

    printf("Established connexion to CA at address %s:%d\n", CA_IP, CA_PORT);

    // function that implements the CSR protocol.
    if (send_CSR_wait_cert(sockfd, CSR, &root_cert, &cert) == 1)
    {
        fprintf(stderr, "Failed to request certificate from CA.\n");
        ret = 1;
        goto end;
    }

    // write the received certificates
    if (write_cert(root_cert, root_cert_filename) == 1)
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
    printf("TLS certificate and root certificate written in %s and %s.\n", TLS_cert_filename, root_cert_filename);

end:
    EVP_PKEY_free(priv_key);
    X509_free(root_cert);
    X509_free(cert);
    X509_REQ_free(CSR);
    close(sockfd);
    printf("Connexion with CA closed.\n");
    return ret;
}