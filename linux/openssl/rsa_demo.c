#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#define KEY_LENGTH 2048
#define PUB_EXP 3
#define PRINT_KEYS
#define WRITE_TO_FILE
int padding = RSA_PKCS1_PADDING;

char publicKey[] = "-----BEGIN PUBLIC KEY-----\n"
                   "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"
                   "ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"
                   "vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"
                   "fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"
                   "i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"
                   "PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"
                   "wQIDAQAB\n"
                   "-----END PUBLIC KEY-----\n";

RSA * create_RSA(unsigned char * key,int mode)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(mode)
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

int public_encrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *encrypted)
{
    RSA *rsa = create_RSA(key, 1);
    int result = RSA_public_encrypt(data_len, data, encrypted, rsa, padding);
    return result;
}

int private_decrypt(unsigned char *enc_data, int data_len, unsigned char *key, unsigned char *decrypted)
{
    RSA *rsa = create_RSA(key, 0);
    int result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
    return result;
}

int private_encrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *encrypted)
{
    RSA *rsa = create_RSA(key, 0);
    int result = RSA_private_encrypt(data_len, data, encrypted, rsa, padding);
    return result;
}

int public_decrypt(unsigned char *enc_data, int data_len, unsigned char *key, unsigned char *decrypted)
{
    RSA *rsa = create_RSA(key, 1);
    int result = RSA_public_decrypt(data_len, enc_data, decrypted, rsa, padding);
    return result;
}

void printLastError(char *msg)
{
    char *err = malloc(130);
    ;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n", msg, err);
    free(err);
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
    //PEM_write_bio_RSAPublicKey(pub, keypair);
    PEM_write_bio_RSA_PUBKEY(pub, keypair);

    pri_key_len = BIO_pending(pri);
    pub_key_len = BIO_pending(pub);
    printf("\nlen1:%ld\nlen2:%ld \n", pri_key_len,pub_key_len);
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

    RSA *pub1= create_RSA((unsigned char *)pub_key,1);
    RSA *pri1= create_RSA((unsigned char *)pri_key,0);

    encrypt = malloc(RSA_size(keypair));
    decrypt = malloc(RSA_size(keypair));
    int len = public_encrypt(msg, strlen(msg), pub_key, encrypt);
    if (len == -1)
    {
        printLastError("Public Encrypt failed ");
        exit(0);
    }
    printf("Encrypted length =%d\n", len);

    int decrypted_length = private_decrypt(encrypt, len, pri_key, decrypt);
    if (decrypted_length == -1)
    {
        printLastError("Private Decrypt failed ");
        exit(0);
    }
    printf("Decrypted Text =%s\n", decrypt);
    printf("Decrypted Length =%d\n", decrypted_length);

    len = private_encrypt(msg, strlen(msg), pri_key, encrypt);
    if (len == -1)
    {
        printLastError("Private Encrypt failed");
        exit(0);
    }
    printf("Encrypted length =%d\n", len);

    decrypted_length = public_decrypt(encrypt, len, pub_key, decrypt);
    if (decrypted_length == -1)
    {
        printLastError("Public Decrypt failed");
        exit(0);
    }
    printf("Decrypted Text =%s\n", decrypt);
    printf("Decrypted Length =%d\n", decrypted_length);

free_stuff:
    RSA_free(keypair);
    BIO_free_all(pub);
    BIO_free_all(pri);
    free(pri_key);
    free(pub_key);
    free(encrypt);
    free(decrypt);
    //free(err);

    return 0;
}