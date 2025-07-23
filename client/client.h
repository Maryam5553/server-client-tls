#ifndef CLIENT_H
#define CLIENT_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "../tools/ssl_err.h"

#define CLIENT_CERT_FILENAME "client_cert.pem"
#define CLIENT_KEY_FILENAME "client_key.pem"
#define CLIENT_CN "client"
#define SERV_PORT 8081
#define SERV_HOSTNAME "server"
#define CLIENT_ROOT_CERT "CA_cert.pem"

// create ctx object and set options
int init_ctx(SSL_CTX **ctx);

// load client and CA certificates
int load_priv_files(SSL_CTX **ctx);

// connect to server and perform TLS handshake
int connect_to_server(SSL_CTX **ctx, SSL **ssl, int *sock);

// write data on the open connection
int send_data(SSL **ssl, const char *data);

int read_data(SSL **ssl);

// close connection with server
int shutdown_con(SSL_CTX **ctx, SSL **ssl);

#endif