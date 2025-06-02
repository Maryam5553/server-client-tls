#ifndef SERIALIZATION_H
#define SERIALIZATION_H

#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <string.h>

#define BUF_SIZE_SERIAL 1024

/* Encode CSR to a buffer in PEM format. */
int encode_CSR_to_buf(X509_REQ *CSR, char *buf);

/* Takes in parameter a TLS certificate in PEM format.
Returns the certificate as a X509 object, or NULL in case of error.
After calling this function you will need to X509_free
the return value (in case of success only). */
X509 *decode_cert_from_buf(char *buf);

/* Takes in parameter a CSR in PEM format.
Returns the CSR as a X509_REQ object, or NULL in case of error.
After calling this function you will need to X509_REQ_free
the return value (in case of success only). */
X509_REQ *decode_CSR_from_buf(char *buf);

/* Encode a TLS certificate to a buffer in PEM format. */
int encode_CERT_to_buf(X509 *cert, char *buf);

/* Returns 1 if buffer contains a CSR in PEM format, 0 otherwise */
int is_csr(char *buf);

/* Returns 1 if buffer contains a TLS certificate in PEM format, 0 otherwise */
int is_tls_certificate(char *buf);

#endif