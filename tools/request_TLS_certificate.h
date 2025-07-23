#ifndef REQUEST_TLS_CERTIFICATE_H
#define REQUEST_TLS_CERTIFICATE_H

#include "connect_to_CA.h"
#include "gen_credentials.h"

// Requests a TLS certificate from CA: establish a connexion with CA,
// performing the protocol of creating a CSR and getting the root certificate and TLS certificate
// sent by CA, and write both certificates in the file given in parameters.
// CA ip and port are hardcoded in connect_to_CA.h
int request_TLS_certificate(char *keyfile_name, const unsigned char *CN, char *root_cert_filename, char *TLS_cert_filename);

#endif