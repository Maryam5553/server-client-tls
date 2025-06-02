#ifndef CONNECT_TO_CA_H
#define CONNECT_TO_CA_H

#include "serialization.h"

#include <unistd.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/x509.h>

// info in CA.c
#define CA_CERT "CA_cert.pem"
#define CA_KEY "CA_key.pem"
#define CA_NAME "CA"
#define CA_PORT 8082
#define CA_IP "127.0.0.1"

// Connects to the CA server, using the values CA_PORT and CA_IP defined in connect_to_CA.h
// Returns socket fd, or -1 in case of error.
int connect_to_CA();

// Blocking: wait for the server to send a certificate.
// sockfd is the opened connexion to the CA server.
// After calling this function you will need to free the return value with X509_free
X509 *wait_for_cert(int sockfd);

// Sends a Certificate Signing Request to the CA, waits for the CA
// to send back a TLS Certificate.
// CA will first send the root certificate used as a trusted certificate,
// then the client certificate requested.
// sockfd is the opened connexion to the CA server.
// In case of success, returns the root certificate and client certificate sent by the CA.
// No need to allocate cert (X509_new) but after calling this function
// you will need to free both certificates with X509_free (in case of success only)
int send_CSR_wait_cert(int sockfd, X509_REQ *CSR, X509 **CA_root_cert, X509 **TLS_cert);

#endif