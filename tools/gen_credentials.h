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

// Generate a TLS certificate, using the key given in parameter
int gen_cert(char *filename, EVP_PKEY *pkey);

#endif