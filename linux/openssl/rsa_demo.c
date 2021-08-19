#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#define KEY_LENGTH 2048
#define PUB_EXP 3
#define PRINT_KEYS
#define WRITE_TO_FILE
RSA * createRSA(unsigned char * key,int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }
 
    return rsa;
}

int main(void)
{
    size_t pri_key_len;           // Length of private key
    size_t pub_key_len;           // Length of public key
    char *pri_key;            // Private key
    char *pub_key;            // Public key
    char msg[KEY_LENGTH / 8]; // Message to encrypt
    char *encrypt = NULL;     // Encrypted message
    char *decrypt = NULL;     // Decrypted message
    char *err;                // Buffer for any error messages

    // Generate key pair
    printf("Generating RSA (%d bits) keypair...", KEY_LENGTH);
    fflush(stdout);
    RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);

    // To get the C-string PEM form:
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    pri_key_len = BIO_pending(pri);
    pub_key_len = BIO_pending(pub);

    pri_key = malloc(pri_key_len + 1);
    pub_key = malloc(pub_key_len + 1);

    BIO_read(pri, pri_key, pri_key_len);
    BIO_read(pub, pub_key, pub_key_len);

    pri_key[pri_key_len] = '\0';
    pub_key[pub_key_len] = '\0';

#ifdef PRINT_KEYS
    printf("\n%s\n%s\n", pri_key, pub_key);
#endif
    printf("done.\n");

    // Get the message to encrypt
    printf("Message to encrypt: ");
    fgets(msg, KEY_LENGTH - 1, stdin);
    msg[strlen(msg) - 1] = '\0';

    RSA *pub1= createRSA((unsigned char *)pub_key,1);
    //RSA *p_pub1 = &pub1;
    // if((pub1 = PEM_read_bio_RSAPublicKey(pub,&pub1,NULL,NULL)) == NULL)
    // {
    //     printf("error\n");
    //     //return 0;
    // }

    // Encrypt the message
    encrypt = malloc(RSA_size(keypair));
    int encrypt_len;
    err = malloc(130);
    if ((encrypt_len = RSA_public_encrypt(strlen(msg) + 1, (unsigned char *)msg, (unsigned char *)encrypt,
                                          keypair, RSA_PKCS1_OAEP_PADDING)) == -1)
    {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error encrypting message: %s\n", err);
        goto free_stuff;
    }

#ifdef WRITE_TO_FILE
    // Write the encrypted message to a file
    FILE *out = fopen("out.bin", "w");
    fwrite(encrypt, sizeof(*encrypt), RSA_size(keypair), out);
    fclose(out);
    printf("Encrypted message written to file.\n");
    free(encrypt);
    encrypt = NULL;

    // Read it back
    printf("Reading back encrypted message and attempting decryption...\n");
    encrypt = malloc(RSA_size(keypair));
    out = fopen("out.bin", "r");
    fread(encrypt, sizeof(*encrypt), RSA_size(keypair), out);
    fclose(out);
#endif

    // Decrypt it
    decrypt = malloc(encrypt_len);
    if (RSA_private_decrypt(encrypt_len, (unsigned char *)encrypt, (unsigned char *)decrypt,
                            keypair, RSA_PKCS1_OAEP_PADDING) == -1)
    {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error decrypting message: %s\n", err);
        goto free_stuff;
    }
    printf("Decrypted message: %s\n", decrypt);

free_stuff:
    RSA_free(keypair);
    BIO_free_all(pub);
    BIO_free_all(pri);
    free(pri_key);
    free(pub_key);
    free(encrypt);
    free(decrypt);
    free(err);

    return 0;
}