#include "server.h"

int init_ctx(SSL_CTX **ctx)
{
    // create context
    *ctx = SSL_CTX_new(TLS_server_method());
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

    // use server cipher preference instead of client preference
    SSL_CTX_set_options(*ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    return 0;
}

int load_priv_files(SSL_CTX **ctx)
{
    // load server certificate chain
    if (SSL_CTX_use_certificate_chain_file(*ctx, SERV_CERT_FILENAME) <= 0)
    {
        printf("Failed to load server certificate chain from \"%s\"", SERV_CERT_FILENAME);
        handle_err("", ctx);
        return 1;
    }

    // load server private key
    if (SSL_CTX_use_PrivateKey_file(*ctx, SERV_KEY_FILENAME, SSL_FILETYPE_PEM) <= 0)
    {
        printf("Failed to load server key from \"%s\", or key doesn't match certificate \"%s\"", SERV_KEY_FILENAME, SERV_CERT_FILENAME);
        handle_err("", ctx);
        return 1;
    }

    // request client certificate, connexion fails if no certificate is sent. TODO revocation list
    SSL_CTX_set_verify(*ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    // root CA certificate to accept client certificate
    if (SSL_CTX_load_verify_file(*ctx, SERV_ROOT_CERT) == 0)
    {
        printf("Failed to load CA file from \"%s\"", SERV_ROOT_CERT);
        handle_err("", ctx);
        return 1;
    }
    return 0;
}

int init_listen(SSL_CTX **ctx, BIO **bio)
{
    // creates bio object needed to create socket. records the intended port without creating the socket
    *bio = BIO_new_accept(SERV_PORT);
    if (*bio == NULL)
    {
        handle_err("Error creating bio", ctx);
        return 1;
    }

    // avoid startup failures if there are still lingering client connections
    // allows several socket to bind to the same port
    BIO_set_bind_mode(*bio, BIO_BIND_REUSEADDR);

    // server starts listening
    if (BIO_do_accept(*bio) <= 0)
    {
        handle_err("Error setting up server socket", ctx);
        return 1;
    }

    return 0;
}

void handle_client_error(char *err_msg, SSL **ssl)
{
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "%s\n", err_msg);
    SSL_free(*ssl); // this also frees the client_bio
}

int handle_client_connection(SSL_CTX **ctx, BIO **client_bio, SSL **ssl)
{
    // associate connexion to SSL handle
    *ssl = SSL_new(*ctx);
    if (*ssl == NULL)
    {
        handle_client_error("Couldn't create SSL handle for client", ssl);
        return 1;
    }
    SSL_set_bio(*ssl, *client_bio, *client_bio);

    printf("Waiting for client to initiate TLS handshake...\n");
    // attempt SSL handshake with the client
    if (SSL_accept(*ssl) <= 0)
    {
        handle_client_error("Error performing SSL handshake with client", ssl); // TODO segfault when client fails
        return 1;
    }

    printf("TLS handshake completed. Client connected securely.\n");
    return 0;
}

int treat_client(SSL **ssl)
{
    while (1)
    {
        char buf[2048] = {0};
        int res = 1;
        // clear possible read/write error from previous loop
        ERR_clear_error();
        // READ
        size_t nb_read = 0;
        res = SSL_read_ex(*ssl, buf, sizeof(buf), &nb_read);
        if (res <= 0)
        {
            fprintf(stderr, "error reading data.\n");
            if (handle_read_write_err(*ssl, res) == 1)
            {
                // if read error is fatal, stop
                return 1;
            }
            else
            {
                // non-fatal error: try reading again
                continue;
            }
        }
        // print message read on the connection
        printf("Read: \"%s\".\n", buf);

        // WRITE
        size_t nb_written = 0;
        res = SSL_write_ex(*ssl, buf, nb_read, &nb_written);
        if (res > 0 && nb_written == nb_read)
        {
            printf("Wrote: \"%s\".\n", buf);
        }
        else
        {
            fprintf(stderr, "Error writing data.\n");
            if (handle_read_write_err(*ssl, res) == 1)
            {
                // if write error is fatal, stop
                return 1;
            }
        }
    }
    return 0;
}
