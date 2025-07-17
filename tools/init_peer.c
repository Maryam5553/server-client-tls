#include "init_peer.h"

int init_peer(peer_info *peer_info)
{
    if (!file_exists(peer_info->pkey_filename))
    {
        printf("Generating %s...\n", peer_info->pkey_filename);
        if (gen_keyfile(peer_info->pkey_filename) == 1)
        {
            fprintf(stderr, "Failed to generate %s.", peer_info->pkey_filename);
            return 1;
        }
        printf("%s generated.\n", peer_info->pkey_filename);
    }
    else
    {
        printf("%s already exists.\n", peer_info->pkey_filename);
    }

    if (!file_exists(peer_info->TLS_cert_filename))
    {
        printf("Requesting TLS certificate...\n");

        EVP_PKEY *priv_key = read_key(peer_info->pkey_filename);
        if (priv_key == NULL)
        {
            fprintf(stderr, "Couldn't read private key from %s.", peer_info->pkey_filename);
            return 1;
        }

        if (request_TLS_certificate(priv_key, peer_info->CN, peer_info->root_cert_filename, peer_info->TLS_cert_filename) == 1)
        {
            fprintf(stderr, "Failed to request a TLS certificate.");
            EVP_PKEY_free(priv_key);
            return 1;
        }

        printf("TLS certificate and root certificate written in %s and %s.\n", peer_info->TLS_cert_filename, peer_info->root_cert_filename);
        EVP_PKEY_free(priv_key);
    } else{
        printf("%s already exists.\n",peer_info->TLS_cert_filename);
    }


    printf("Done initializing peer.\n");
    return 0;
}