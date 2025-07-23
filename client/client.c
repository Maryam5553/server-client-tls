#include "client.h"

int init_ctx(SSL_CTX **ctx)
{
    // create context
    *ctx = SSL_CTX_new(TLS_client_method());
    if (*ctx == NULL)
    {
        handle_err("Failed to create context", ctx);
        return 1;
    }

    // set min TLS version to 1.3
    if (!SSL_CTX_set_min_proto_version(*ctx, TLS1_3_VERSION))
    {
        handle_err("Failed to set min TLS version to 1.3", ctx);
        return 1;
    }

    return 0;
}

int load_priv_files(SSL_CTX **ctx)
{
    // load client certificate chain
    if (SSL_CTX_use_certificate_chain_file(*ctx, CLIENT_CERT_FILENAME) <= 0)
    {
        printf("Failed to load client certificate chain from \"%s\"", CLIENT_CERT_FILENAME);
        handle_err("", ctx);
        return 1;
    }

    // load client private key
    if (SSL_CTX_use_PrivateKey_file(*ctx, CLIENT_KEY_FILENAME, SSL_FILETYPE_PEM) <= 0)
    {
        printf("Failed to load client key from \"%s\", or key doesn't match certificate \"%s\"", CLIENT_KEY_FILENAME, CLIENT_CERT_FILENAME);
        handle_err("", ctx);
        return 1;
    }

    // verify server certificate
    SSL_CTX_set_verify(*ctx, SSL_VERIFY_PEER, NULL);

    // root CA certificate accepted for the server
    if (SSL_CTX_load_verify_file(*ctx, CLIENT_ROOT_CERT) == 0)
    {
        printf("Failed to load CA file from \"%s\"", CLIENT_ROOT_CERT);
        handle_err("", ctx);
        return 1;
    }
    return 0;
}

int connect_to_server(SSL_CTX **ctx, SSL **ssl, int *sock)
{
    // create SSL object
    *ssl = SSL_new(*ctx);
    if (*ssl == NULL)
    {
        handle_err("Couldn't create SSL connection", ctx);
        return 1;
    }

    // create TCP socket
    *sock = socket(AF_INET, SOCK_STREAM, 0);
    if (*sock == -1)
    {
        handle_err("Couldn't create socket", ctx);
        return 1;
    }

    // server info
    struct sockaddr_in serveraddr = {
        .sin_family = AF_INET,
        .sin_port = htons(SERV_PORT),
        .sin_addr.s_addr = inet_addr("127.0.0.1")};

    if (inet_pton(AF_INET, "127.0.0.1", &serveraddr.sin_addr) <= 0)
    {
        close(*sock);
        handle_err("Failed to convert server address", ctx);
        return 1;
    }

    // connect
    if (connect(*sock, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) == -1)
    {
        close(*sock);
        handle_err("Couldn't connect to server", ctx);
        return 1;
    }

    printf("Connexion to the server at address 127.0.0.1:%d.\n",SERV_PORT);

    // create BIO object to wrap the socket

    BIO *bio;
    bio = BIO_new(BIO_s_socket());
    if (bio == NULL)
    {
        BIO_closesocket(*sock);
        handle_err("Couldn't create BIO object", ctx);
        return 1;
    }
    BIO_set_fd(bio, *sock, BIO_CLOSE);
    SSL_set_bio(*ssl, bio, bio); // don't close BIO after this step, simply close socket

    // pour savoir à quel serveur se connecter
    if (!SSL_set_tlsext_host_name(*ssl, SERV_HOSTNAME))
    {
        printf("Failed to set the SNI hostname\n");
        BIO_closesocket(*sock);
        handle_err("", ctx);
        return 1;
    }
    // pour connaître le hostname qu'on attend dans le certificat
    if (!SSL_set1_host(*ssl, SERV_HOSTNAME))
    {
        printf("Failed to set the certificate verification hostname");
        BIO_closesocket(*sock);
        handle_err("", ctx);
        return 1;
    }

    // perform TLS handshake
    printf("Initiating TLS handshake with the server\n");
    if (SSL_connect(*ssl) < 1)
    {
        fprintf(stderr, "TLS handshake failed\n");
        fprintf(stderr, "Verify error: %s\n", X509_verify_cert_error_string(SSL_get_verify_result(*ssl)));
        BIO_closesocket(*sock);
        handle_err("", ctx);
        return 1;
    }

    printf("TLS handshake was successful. Client connected securely.\n");

    return 0;
}

int send_data(SSL **ssl, const char *data)
{
    size_t nb_written;

    ERR_clear_error(); // clear possible previous read/write error
    int res = SSL_write_ex(*ssl, data, strlen(data), &nb_written);
    if (res <= 0)
    {
        fprintf(stderr, "Failed to write data to the server.");
        handle_read_write_err(*ssl, res); // print err
        return 1;
    }
    printf("Wrote: \"%s\"\n", data);
    return 0;
}

int read_data(SSL **ssl)
{
    char buf[2048] = {0};
    size_t nb_read = 0;

    ERR_clear_error(); // clear possible previous read/write error
    int res = SSL_read_ex(*ssl, buf, sizeof(buf), &nb_read);
    if (res <= 0)
    {
        fprintf(stderr, "Error reading data.");
        handle_read_write_err(*ssl, res); // print err
        return 1;
    }
    printf("Read: \"%s\".\n", buf);
    return 0;
}

int shutdown_con(SSL_CTX **ctx, SSL **ssl)
{
    int ret = SSL_shutdown(*ssl);
    if (ret == 0)
    {
        // we sent a close_notify but didn't receive one back
        // so now we're making a second call to SSL_shutdown to wait for the peer's close_notify.
        printf("Sent close_notify to the server.\n");
        ret = SSL_shutdown(*ssl);
        if (ret == 1)
        {
            printf("Shutdown completed.\n");
            return 0;
        }
    }
    else if (ret < 1)
    {
        handle_err("error shutting down", ctx);
        return 1;
    }
    return 1;
}
