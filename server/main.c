#include "server.h"
#include "../tools/setup_peer.h"

int main()
{
    SSL_CTX *ctx = NULL;
    /* BIO used to accept incoming connections.
     when a  new connection is established, a new BIO socket is created for
     the client (client_bio) and appended to this BIO. We'll then pop the
     client BIO so that the accept_bio can await new connections. */
    BIO *accept_bio = NULL;

    // Generate private files
    peer_info serv_info = {"server", SERV_KEY_FILENAME, SERV_CERT_FILENAME, SERV_ROOT_CERT, SERV_CN};

    printf("***** SERVER SETUP *****\n");
    if (setup_peer(&serv_info) == 1)
    {
        fprintf(stderr, "failed to generate server private files.");
        return EXIT_FAILURE;
    }
    printf("***** SETUP DONE *****\n\n");

    // init connexion
    if (init_ctx(&ctx) == 1)
        return EXIT_FAILURE;

    if (load_priv_files(&ctx) == 1)
        return EXIT_FAILURE;

    if (init_listen(&ctx, &accept_bio) == 1)
        return EXIT_FAILURE;

    printf("Server listening on port %s...\n", SERV_PORT);

    // Client loop
    while (1)
    {
        BIO *client_bio = NULL;
        SSL *ssl = NULL;

        ERR_clear_error();
        if (BIO_do_accept(accept_bio) <= 0)
        {
            // client went away before we accepted the connection
            continue;
        }
        printf("New client\n");

        client_bio = BIO_pop(accept_bio);
        if (handle_client_connection(&ctx, &client_bio, &ssl) == 1)
            continue;

        printf("Client connected securely.\n");

        if (treat_client(&ssl) == 1)
            continue;

        SSL_free(ssl);
    }

    BIO_free(accept_bio);
    SSL_CTX_free(ctx);
    return EXIT_SUCCESS;
}