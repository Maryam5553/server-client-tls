#ifndef INIT_PEER_H
#define INIT_PEER_H

#include "gen_credentials.h"
#include "request_TLS_certificate.h"
#include "file_exists.h"

typedef struct
{
    char *pkey_filename;      // peer private key
    char *TLS_cert_filename;  // peer personate TLS certificate
    char *root_cert_filename; // certificate sent by CA used as root cert for peer private cert
    unsigned char *CN;        // Common Name to put in certificate subject
} peer_info;

// Checks if peer private key and TLS certificate exists. If private key doesn't exist, generates one.
// If TLS certificate doesn't exist, requests a certificate from CA.
int init_peer(peer_info *peer_info);

#endif