#include "ssl_err.h"
#include <errno.h>

// print openssl err and free context
void handle_err(char *err_msg, SSL_CTX **ctx)
{
    SSL_CTX_free(*ctx);
    ERR_print_errors_fp(stderr);
    printf("\n");
    fprintf(stderr, "%s.", err_msg);
}

// send close_notify to the peer, after receiving a close_notify message from the peer.
int shut_back(SSL *ssl)
{
    int ret = SSL_shutdown(ssl);
    if (ret == 1)
    {
        printf("Sent close_notify to the peer. Connexion successfully closed.\n");
        return 0;
    }
    else if (ret == 0)
    {
        fprintf(stderr, "Sent close_notify to the peer, but the peer hasn't sent a close_notify.");
        return 1;
    }
    else
    {
        fprintf(stderr, "Shutdown has failed.");
        SSL_get_error(ssl, ret);
        return 1;
    }
}

// Takes err code from SSL_read or SSL_write.
// Returns 1 if some non-recoverable, fatal error occurred
// (which means we can't read/write on the channel anymore); 0 if not.
// Prints result of SSL_get_error() in a human-readable message.
int handle_read_write_err(SSL *ssl, int ret_code)
{
    int err_code = SSL_get_error(ssl, ret_code);
    char buf[256];

    // see https://docs.openssl.org/master/man3/SSL_get_error/#return-values
    switch (err_code)
    {
        /* FATAL ERRORS */

    case SSL_ERROR_SYSCALL:
        // check openssl error queue
        ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
        fprintf(stderr, "%s", buf);
        // check errno (with perror)
        perror("SSL read/write failed");
        // don't call SSL_shutdown() after this error occurs
        return 1;
    case SSL_ERROR_SSL:
        // check openssl error queue
        ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
        fprintf(stderr, "%s", buf);
        // don't call SSL_shutdown() after this error occurs
        return 1;
    case SSL_ERROR_ZERO_RETURN:
        // peer sent a close_notify, we will now try to sent a close_notify to close the connexion.
        fprintf(stderr, "The peer has closed the connection for writing by sending the close_notify alert.");
        shut_back(ssl);
        // wether shut_back has succeeded or not, we have close the connexion on our side, so we should stop reading.
        return 1;

        /* NON FATAL ERRORS */

    case SSL_ERROR_NONE:
        fprintf(stderr, "No SSL error.");
        return 0;
    case SSL_ERROR_WANT_READ:
        fprintf(stderr, "The operation did not complete and can be retried later");
        return 0;
    case SSL_ERROR_WANT_WRITE:
        fprintf(stderr, "The operation did not complete and can be retried later");
        return 0;
    case SSL_ERROR_WANT_CONNECT:
        fprintf(stderr, "The operation did not complete; the same TLS/SSL I/O function should be called again later. ");
        return 0;
    case SSL_ERROR_WANT_ACCEPT:
        fprintf(stderr, "The operation did not complete; the same TLS/SSL I/O function should be called again later. ");
        return 0;
    case SSL_ERROR_WANT_X509_LOOKUP:
        fprintf(stderr, "The operation did not complete because an application callback set by SSL_CTX_set_client_cert_cb() has asked to be called again.");
        return 0;
    case SSL_ERROR_WANT_ASYNC:
        fprintf(stderr, "The operation did not complete because an asynchronous engine is still processing data.");
        return 0;
    case SSL_ERROR_WANT_ASYNC_JOB:
        fprintf(stderr, "The asynchronous job could not be started because there were no async jobs available in the pool.");
        return 0;
    case SSL_ERROR_WANT_CLIENT_HELLO_CB:
        fprintf(stderr, "The operation did not complete because an application callback set by SSL_CTX_set_client_hello_cb() has asked to be called again.");
        return 0;
    default:
        return 0;
    }
}