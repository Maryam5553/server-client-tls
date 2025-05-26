#ifndef GEN_CREDENTIALS_H
#define GEN_CREDENTIALS_H

#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>

// Write key pair in the file given in parameter (creating the file if necessary).
// If a file of the same name already exists, the contents will be overwritten.
// And if the key couldn't be written, the file will be deleted.
int gen_keyfile(char *filename);

// Read the key in the file given in parameter.
// No need to allocate EVP_PKEY (with EVP_PKEY_new), but after this function
// you need to free the key with EVP_PKEY_free (only in case of success).
// Returns NULL if didn't work.
EVP_PKEY *read_key(char *filename);

// Create a subject name to put in the certificate.
// TODO for the moment we can only add the Common Name (mandatory), but typically this can include
// more information on the user (optionally).
// No need to allocate X509_NAME (with X509_NAME_new), but after this function
// you need to free the key with X509_NAME_free (only in case of success).
// Returns NULL if didn't work.
X509_NAME *make_subject_name(const unsigned char *user_CN);

// TODO delete file if generation failed
// TODO provide option to not overwrite existing files ?
// Generate a TLS certificate, using the key given in parameter.
// user_key/user_name are the key/information of the entity of the certificate.
// root_key/issuer_name are the key/information of the entity signing the certificate (CA).
// User and Issuer subject names can be created with make_subject_name().
// For a self_signed certifiate, user and issuer are the same entity.
int gen_cert(char *filename, EVP_PKEY *user_key, EVP_PKEY *root_key, X509_NAME *user_name, X509_NAME *issuer_name);

// TODO delete file if generation failed
// Generate a certificate signing request and write it in file given in parameter.
// Provide the key used to sign the CSR and the Common Name.
int gen_CSR_file(EVP_PKEY *key, const unsigned char *CN, char *filename);

// Read a Certificate Signing Request file.
// No need to allocate X509_REQ (with X509_REQ_new), but after this function
// you need to free the CSR with X509_REQ_free (only in case of success).
// Returns NULL if the CSR couldn't be read.
X509_REQ *read_CSR(char *filename);

// Takes in parameter a CSR, and generate a certificate using the information of the CSR.
// root_key and issuer_name are the info of the certificate signing authority.
int gen_cert_from_CSR(X509_REQ *CSR, char *cert_filename, EVP_PKEY *root_key, X509_NAME *issuer_name);

#endif