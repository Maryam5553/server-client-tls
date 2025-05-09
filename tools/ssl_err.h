#ifndef SSL_ERR_H
#define SSL_ERR_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>

void handle_err(char *err_msg, SSL_CTX **ctx);
int  handle_read_write_err(SSL *ssl, int ret_code);

#endif