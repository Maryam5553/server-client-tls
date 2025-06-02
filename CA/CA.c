#include "../tools/file_exists.h"
#include "../tools/gen_credentials.h"
#include "../tools/serialization.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define CA_CERT "CA_cert.pem"
#define CA_KEY "CA_key.pem"
#define CA_NAME "CA"
#define CA_PORT 8082
#define BUF_SIZE_CA 1024

// Generate CA root key and certificate (if didn't already exist).
int init_CA(char *CA_root_cert, char *CA_root_key, char *CA_name)
{
    EVP_PKEY *key = NULL;
    X509_NAME *subject_name = NULL;
    int ret = 0;

    // if the file doesn't exist, let's generate a CA private key
    if (!file_exists(CA_root_key))
    {
        if (gen_keyfile(CA_root_key) == 1)
        {
            fprintf(stderr, "Couldn't generate keyfile %s.\n", CA_root_key);
            return 1;
        }
        printf("Keyfile %s successfully generated.\n", CA_root_key);
    }

    // if it doesn't exist, let's generate a self-signed certificate
    // that will be used as a root certificate
    if (!file_exists(CA_root_cert))
    {
        // load key
        key = read_key(CA_root_key);
        if (key == NULL)
        {
            fprintf(stderr, "Couldn't read keyfile %s.\n", CA_root_key);
            return 1;
        }

        // generate self-signed certificate
        subject_name = make_subject_name(CA_name);
        if (gen_cert_file(CA_root_cert, key, key, subject_name, subject_name) == 1)
        {
            fprintf(stderr, "Couldn't generate TLS certificate file %s.\n", CA_root_cert);
            return 1;
        }
        printf("TLS certificate %s successfully generated.\n", CA_root_cert);
    }

end:
    X509_NAME_free(subject_name);
    EVP_PKEY_free(key);
    return ret;
}

// CA starts listening to incoming connexions.
// Returns socket fd, or -1 in case of error.
int launch_CA(uint16_t CA_port)
{
    // create a socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("creation of socket failed");
        return -1;
    }

    // fill in server address
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_port = htons(CA_port);
    address.sin_addr.s_addr = INADDR_ANY;

    // bind address to the socket
    if (bind(sock, (struct sockaddr *)&address, sizeof(struct sockaddr_in)) < 0)
    {
        perror("bind socket failed");
        close(sock);
        return -1;
    }

    // prepare to accept incoming connexions
    if (listen(sock, 0) < 0)
    {
        perror("listen failed");
        close(sock);
        return -1;
    }
    return sock;
}

// Load info necessary for generating TLS certificates: CA key, CA root certificate,
// and the subject contained in CA root certificate
int load_CA_info(char *CA_root_keyfile, char *CA_certfile, EVP_PKEY **root_key, X509 **root_cert, X509_NAME **CA_name)
{
    EVP_PKEY *key;
    X509 *cert;
    X509_NAME *name;
    int ret = 0;

    key = read_key(CA_root_keyfile);
    if (key == NULL)
    {
        fprintf(stderr, "Couldn't load CA private key.\n");
        return 1;
    }

    // extract subject name from CA root certificate
    cert = read_cert(CA_certfile);
    if (cert == NULL)
    {
        fprintf(stderr, "Couldn't load CA root certificate (to extract subject name).\n");
        ret = 1;
        goto end;
    }

    name = X509_get_subject_name(cert); // don't free
    if (name == NULL)
    {
        fprintf(stderr, "Couldn't extract subject name from CA root certificate.\n");
        ret = 1;
        goto end;
    }

    // return values
    *root_key = key;
    *root_cert = cert;
    *CA_name = name;

end:
    if (ret == 1)
    {
        // if not everything was correctly loaded, we'll free the rest
        EVP_PKEY_free(key);
        X509_free(cert);
    }
    return ret;
}

// Protocol to treat incoming CSR requests.
// CA waits for CSR requests. Generates a TLS certificate, and send first
// the root certificate, then the TLS certificate.
int treat_CSR_requests(int client_sockfd, EVP_PKEY *CA_key, X509 *CA_cert, X509_NAME *CA_name)
{
    X509_REQ *CSR;
    X509 *cert;
    char recv_buf[BUF_SIZE_CA];
    char send_root_buf[BUF_SIZE_CA];
    char send_cert_buf[BUF_SIZE_CA];
    int ret = 0;

    printf("Waiting for CSR requests from connected client...\n");
    while (1)
    {
        // wait for CSR requests
        int n = read(client_sockfd, &recv_buf, sizeof(recv_buf));
        if (n < 0)
        {
            perror("error reading request from client");
            return 1;
        }
        else if (n == 0)
        {
            printf("Client closed connexion.\n");
            return 0;
        }
        if (is_csr(recv_buf))
        {
            recv_buf[n] = '\0';
            break;
        }
    }

    // printf("received : %s\n", recv_buf);
    CSR = decode_CSR_from_buf(recv_buf);
    if (CSR == NULL)
    {
        fprintf(stderr, "Error decoding received data.\n");
        ret = 1;
        goto end;
    }

    // TODO essayer de gérer les erreurs pour envoyer au client ce qui a échoué

    // generate certificate (this function only generates a certificate if CSR is valid)
    cert = gen_cert_from_CSR(CSR, CA_key, CA_name); // TODO retourner une chaîne de caractère avec le pourquoi la génération a échoué ? (ex CSR pas valide)
    if (cert == NULL)
    {
        fprintf(stderr, "Error generating client certificate.\n");
        ret = 1;
        goto end;
    }

    printf("Client certificate generated.\n");

    // prepare to send root and client certificate
    if (encode_CERT_to_buf(CA_cert, send_root_buf))
    {
        fprintf(stderr, "Error encoding root certificate.\n");
        ret = 1;
        goto end;
    }

    if (encode_CERT_to_buf(cert, send_cert_buf) == 1)
    {
        fprintf(stderr, "Error encoding client certificate.\n");
        ret = 1;
        goto end;
    }

    // send both certificates

    printf("Sending root certificate...\n");
    if (write(client_sockfd, send_root_buf, sizeof(send_root_buf)) < 0)
    {
        perror("error writing root certificate to client");
        return 1;
        goto end;
    }
    printf("Root certificate sent.\n");

    printf("Sending client certificate...\n");
    if (write(client_sockfd, send_cert_buf, sizeof(send_cert_buf)) < 0)
    {
        perror("error writing TLS certificate to client");
        return 1;
        goto end;
    }
    printf("Certificate sent to client!\n");

    printf("Done treating the CSR request.\n");
end:
    X509_REQ_free(CSR);
    X509_free(cert);
    return ret;
}

// TODO test CA and client communication protocole between CA and test_connect_to_CA

int main()
{
    int sockfd;
    EVP_PKEY *root_key;
    X509 *root_cert;
    X509_NAME *CA_name; // never free this value, as it will be loaded with X509_get_subject_name.

    if (init_CA(CA_CERT, CA_KEY, CA_NAME) == 1)
    {
        fprintf(stderr, "Failure to initialize CA.\n");
        return 1;
    }
    printf("CA initialized.\n");

    if (load_CA_info(CA_KEY, CA_CERT, &root_key, &root_cert, &CA_name) == 1)
    {
        fprintf(stderr, "Failure to load CA info.\n");
        return 1;
    }
    printf("root key and CA name loaded.\n");

    sockfd = launch_CA(CA_PORT);
    if (sockfd < 0)
    {
        fprintf(stderr, "Failure to launch CA.\n");
        return 1;
    }
    printf("CA now accepts incoming connexions.\n");

    // incoming connexions
    while (1)
    {
        struct sockaddr_in client_addr;
        socklen_t size = sizeof(client_addr);
        int client_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, &size);
        if (client_sockfd < 0)
        {
            perror("Incoming connexion failed");
            continue;
        }
        printf("Incoming connexion accepted.\n");

        // treat client request to generate TLS certificates
        if (treat_CSR_requests(client_sockfd, root_key, root_cert, CA_name) == 1)
        {
            fprintf(stderr, "Failure to treat requests from client. Closing connexion.");
            close(client_sockfd);
            continue;
        }

        printf("End of communication with client.\n");
        close(client_sockfd);
    }

    EVP_PKEY_free(root_key);
    X509_free(root_cert);
    close(sockfd);
    return 0;
}