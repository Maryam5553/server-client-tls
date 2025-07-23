#ifndef SERVER_H
#define SERVER_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <stdio.h>
#include "../tools/ssl_err.h"

#define SERV_CERT_FILENAME "serv_cert.pem"
#define SERV_KEY_FILENAME "serv_key.pem"
#define SERV_PORT "8081"
#define SERV_ROOT_CERT "CA_cert.pem"
#define SERV_CN "server"

// create ctx object and set options
int init_ctx(SSL_CTX **ctx);

// load server and CA certificates
int load_priv_files(SSL_CTX **ctx);

// creates BIO object and inits a socket
int init_listen(SSL_CTX **ctx, BIO **bio);

// print errors and free ressources allocated to client
void handle_client_error(char *err_msg, SSL **ssl);
// accept incoming connection and try SSL handshake
int handle_client_connection(SSL_CTX **ctx, BIO **client_bio, SSL **ssl);

// operations to perform when client is connected
int treat_client(SSL **ssl);

#endif