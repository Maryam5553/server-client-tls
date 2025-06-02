#include "connect_to_CA.h"

int connect_to_CA()
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("Creation of socket failed");
        return -1;
    }

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_port = htons(CA_PORT);
    inet_aton(CA_IP, &address.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&address, sizeof(struct sockaddr_in)) < 0)
    {
        perror("Couldn't connect to CA"); // TODO affichage d'adresse
        close(sockfd);
        return -1;
    }

    return sockfd;
}

X509 *wait_for_cert(int sockfd)
{
    X509 *cert;
    char recv_buf[BUF_SIZE_SERIAL];

    while (1)
    {
        int n = read(sockfd, &recv_buf, sizeof(recv_buf));
        if (n < 0)
        {
            perror("Error reading CA answer");
            return NULL;
        }
        else if (n == 0)
        {
            printf("Server closed connexion.\n");
            return NULL;
        }
        if (is_tls_certificate(recv_buf))
        {
            recv_buf[n] = '\0';
            break;
        }
    }

    cert = decode_cert_from_buf(recv_buf);
    if (cert == NULL)
    {
        fprintf(stderr, "Failed to decode root certificate sent by CA.\n");
        return NULL;
    }
    return cert;
}

int send_CSR_wait_cert(int sockfd, X509_REQ *CSR, X509 **CA_root_cert, X509 **TLS_cert)
{
    X509 *root_cert = NULL;
    X509 *cert = NULL;
    char send_buf[BUF_SIZE_SERIAL] = {0};
    int ret = 0;

    // send CSR to CA
    if (encode_CSR_to_buf(CSR, send_buf) == 1)
    {
        fprintf(stderr, "Failed to encode CSR to buffer.\n");
        return 1;
    }

    if (write(sockfd, send_buf, sizeof(send_buf)) < 0)
    {
        perror("Error sending CSR to CA");
        return 1;
    }

    printf("Sent CSR to CA.\n");

    // wait for CA to sent root certificate
    printf("Waiting for CA to send root certificate...\n");
    root_cert = wait_for_cert(sockfd);
    if (root_cert == NULL)
    {
        perror("Couldn't receive CA root certificate.");
        ret = 1;
        goto end;
    }
    printf("Root certificate received.\n");

    // wait for CA to sent TLS cert
    printf("Waiting for CA to send TLS certificate...\n");
    cert = wait_for_cert(sockfd);
    if (cert == NULL)
    {
        perror("Couldn't receive TLS certificate.");
        ret = 1;
        goto end;
    }
    printf("TLS certificate received.\n");

    // return values
    *CA_root_cert = root_cert;
    *TLS_cert = cert;

end:
    if (ret == 1)
    {
        X509_free(root_cert);
        X509_free(cert);
    }
    return ret;
}