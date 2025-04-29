#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <stdio.h>

#define SERV_CERT_FILENAME "serv_cert.pem"
#define SERV_KEY_FILENAME "serv_key.pem"
#define SERV_PORT "8080"

// print openssl err and free context
void handle_err(char *err_msg, SSL_CTX **ctx)
{
    SSL_CTX_free(*ctx);
    ERR_print_errors_fp(stderr);
    printf("\n");
    fprintf(stderr, "%s.", err_msg);
}

// create ctx object and set options
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

// load server certificate and private key
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

    /*Note: Even if a client did present a trusted ceritificate, for it to be useful, the server application would still need custom code to use the verified identity to grant nondefault access to that particular client. Some servers grant access to all clients with certificates from a private CA, this then requires processing of certificate revocation lists to deauthorise a client. It is often simpler and more secure to instead keep a list of authorised public keys.*/
    SSL_CTX_set_verify(*ctx, SSL_VERIFY_NONE, NULL); // TODO change to "verify client cert"
    return 0;
}

// creates BIO object and inits a socket
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

void handle_client_error(char *err_msg, BIO **client_bio, SSL **ssl)
{
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "%s", err_msg);
    SSL_free(*ssl);
    BIO_free(*client_bio);
}

// accept incoming connection and try SSL handshake
int handle_client_connection(SSL_CTX **ctx, BIO **acceptor_bio, BIO **client_bio, SSL **ssl)
{
    // create new bio for the client
    *client_bio = BIO_pop(*acceptor_bio);
    printf("New client\n");

    // associate connexion to SSL handle
    *ssl = SSL_new(*ctx);
    if (*ssl == NULL)
    {
        handle_client_error("Couldn't create SSL handle for client", client_bio, NULL);
        return 1;
    }
    SSL_set_bio(*ssl, *client_bio, *client_bio);

    // attempt SSL handshake with the client
    if (SSL_accept(*ssl) <= 0)
    {
        handle_client_error("Error performing SSL handshake with client", client_bio, ssl);
        return 1;
    }
    return 0;
}

// operations to perform when client is connected
int treat_client(SSL **ssl)
{
    char buf[2048];
    size_t total = 0;
    size_t nread = 0;
    while (SSL_read_ex(*ssl, buf, sizeof(buf), &nread) > 0)
    {
        size_t nwritten = 0;
        if (SSL_write_ex(*ssl, buf, nread, &nwritten) > 0 && nwritten == nread)
        {
            total += nwritten;
            continue;
        }
        printf("Error echoing client input\n");
        return 1;
    }
    return 0;
}

int main()
{
    SSL_CTX *ctx = NULL;
    BIO *bio = NULL;

    if (init_ctx(&ctx) == 1)
        return EXIT_FAILURE;

    if (load_priv_files(&ctx) == 1)
        return EXIT_FAILURE;

    if (init_listen(&ctx, &bio) == 1)
        return EXIT_FAILURE;

    printf("Server listening on port %s.\n", SERV_PORT);

    // client loop
    while (1)
    {
        BIO *client_bio = NULL;
        SSL *ssl = NULL;

        ERR_clear_error();
        if (BIO_do_accept(bio) <= 0)
        {
            /* Client went away before we accepted the connection */
            continue;
        }

        if (handle_client_connection(&ctx, &bio, &client_bio, &ssl) == 1)
            continue;

        printf("Client connected securely.\n");
        if (treat_client(&ssl) == 1)
            continue;

        SSL_free(ssl);
        BIO_free(client_bio);
    }

    BIO_free(bio);
    SSL_CTX_free(ctx);
    return EXIT_SUCCESS;
}