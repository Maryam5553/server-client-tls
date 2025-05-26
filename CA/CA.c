#include "../tools/file_exists.h"
#include "../tools/gen_credentials.h"

#define CA_CERT "CA_cert.pem"
#define CA_KEY "CA_key.pem"
#define CA_NAME "CA"

int init_CA(char *CA_root_cert, char *CA_root_key, char *CA_name)
{
    EVP_PKEY *key = NULL;
    X509_NAME *subject_name = NULL;
    int ret = 0;

    // if the file doesn't exist, let's generate a CA private key
    if (!file_exists(CA_root_key))
    {
        if (gen_keyfile(CA_root_key) == 1)
        {
            fprintf(stderr, "Couldn't generate keyfile %s.\n", CA_root_key);
            return 1;
        }
        printf("Keyfile %s successfully generated.\n", CA_root_key);
    }

    // if it doesn't exist, let's generate a self-signed certificate
    // that will be used as a root certificate
    if (!file_exists(CA_root_cert))
    {
        // load key
        key = read_key(CA_root_key);
        if (key == NULL)
        {
            fprintf(stderr, "Couldn't read keyfile %s.\n", CA_root_key);
            return 1;
        }

        // generate self-signed certificate
        subject_name = make_subject_name(CA_name);
        if (gen_cert(CA_root_cert, key, key, subject_name, subject_name) == 1)
        {
            fprintf(stderr, "Couldn't read keyfile %s.\n", CA_root_key);
            return 1;
        }
        printf("TLS certificate %s successfully generated.\n", CA_root_cert);
    }

end:
    X509_NAME_free(subject_name);
    EVP_PKEY_free(key);
    return ret;
}

int main()
{

    if (init_CA(CA_CERT, CA_KEY, CA_NAME) == 1)
    {
        fprintf(stderr, "Failure to initialize CA.\n");
        return 1;
    }

    printf("CA initialized.\n");

    
    // puis reste allumé pour traiter les requêtes de génération de certificat
    return 0;
}