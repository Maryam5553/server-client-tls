#include "setup_peer.h"

int setup_peer(peer_info *peer_info)
{
    // generate private key (if it doesn't exist)
    if (!file_exists(peer_info->pkey_filename))
    {
        if (gen_keyfile(peer_info->pkey_filename) == 1)
        {
            fprintf(stderr, "Failed to generate %s.", peer_info->pkey_filename);
            return 1;
        }
        printf("%s private key generated in file %s.\n", peer_info->name, peer_info->pkey_filename);
    }
    else
    {
        printf("%s private key %s already exists.\n", peer_info->name, peer_info->pkey_filename);
    }

    // request TLS certificate from CA (if peer doesn't have one)
    if (!file_exists(peer_info->TLS_cert_filename))
    {
        printf("No TLS certificate found: let's request a certificate to CA.\n");

        if (request_TLS_certificate(peer_info->pkey_filename, peer_info->CN, peer_info->root_cert_filename, peer_info->TLS_cert_filename) == 1)
        {
            fprintf(stderr, "Failed to request a TLS certificate.");
            return 1;
        }
    }
    else
    {
        printf("%s TLS certificate %s already exists.\n", peer_info->name, peer_info->TLS_cert_filename);
    }

    return 0;
}