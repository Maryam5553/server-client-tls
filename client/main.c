#include "client.h"
#include "../tools/init_peer.h"

int main()
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int sock = -1;
    int res;

    // Generate private files
    peer_info client_info = {CLIENT_KEY_FILENAME, CLIENT_CERT_FILENAME, CLIENT_ROOT_CERT, CLIENT_CN};

    if (init_peer(&client_info) == 1)
    {
        fprintf(stderr, "failed to generate client private files.");
        res = EXIT_FAILURE;
        goto end;
    }

    // init connection
    if (init_ctx(&ctx) == 1)
    {
        res = EXIT_FAILURE;
        goto end;
    }

    if (load_priv_files(&ctx) == 1)
    {
        res = EXIT_FAILURE;
        goto end;
    }

    // connection
    if (connect_to_server(&ctx, &ssl, &sock) == 1)
    {
        res = EXIT_FAILURE;
        goto end;
    }

    // send and receive data
    const char *data = "hello";
    if (send_data(&ssl, data) == 1)
    {
        res = shutdown_con(&ctx, &ssl);
        goto end;
    }
    if (read_data(&ssl) == 1)
    {
        res = shutdown_con(&ctx, &ssl);
        goto end;
    }

    res = shutdown_con(&ctx, &ssl);

end:
    SSL_free(ssl);
    if (res == 0)
        SSL_CTX_free(ctx);
    return res;
}