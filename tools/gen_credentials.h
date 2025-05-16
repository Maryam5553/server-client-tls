#ifndef GEN_CREDENTIALS_H
#define GEN_CREDENTIALS_H

#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>

// Write key pair in the file given in parameter (creating the file if necessary)
int write_key(EVP_PKEY *key, char *filename);

// Generate a 256 bytes RSA key, and write it in the file given in parameter.
int gen_keyfile(char *filename);

// Read the key in the file given in parameter.
// No need to allocate EVP_PKEY (with EVP_PKEY_new), but after this function
// you need to free the key with EVP_PKEY_free (only in case of success).
// Returns NULL if didn't work.
EVP_PKEY *read_key(char *filename);

// Generate a TLS certificate, using the key given in parameter.
// user_key/user_CN are the key/CN of the entity of the certificate.
// root_key/issuer_CN are the key/CN of the entity signing the certificate (CA).
// For a self_signed certifiate, user and issuer are the same entity.
int gen_cert(char *filename, EVP_PKEY *user_key, EVP_PKEY *root_key, const unsigned char *user_CN, const unsigned char *issuer_CN);

// Generate a certificate signing request and write it in file given in parameter.
int gen_CSR_file(EVP_PKEY *key, const unsigned char *CN, char *filename);

#endif