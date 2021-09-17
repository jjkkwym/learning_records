#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha1.h"
#include "mbedtls/platform.h"
#include "mbedtls/oid.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/error.h"
#include <string.h>
#include "mbedtls/md.h"
#include "mbedtls/entropy.h"
#include "mbedtls/bignum.h"

#define FORMAT_PEM 0
#define FORMAT_DER 1

#define DFL_TYPE MBEDTLS_PK_RSA
#define RSA_KEY_SIZE 2048
#define DFL_FILENAME "keyfile.key"
#define DFL_FORMAT FORMAT_PEM
#define DFL_MD_ALG MBEDTLS_MD_SHA256
#define DFL_SUBJECT_NAME "CN=wrover-dps-99,O=DycodeX,C=ID"

struct options
{
    int type;                 /* the type of key to generate          */
    int rsa_keysize;          /* length of key in bits                */
    const char *subject_name; /* subject name for certificate request */
    int format;               /* the output format to use             */
    mbedtls_md_type_t md_alg; /* Hash algorithm used for signature.   */
} opt;


int gen_rsa_key()
{
    int ret;
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "gen_rsa_key";
    
    mbedtls_pk_init(&key);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    printf("Seeding the random number generator...\n");
    mbedtls_entropy_init(&entropy);
    
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0)
    {
        printf("Failed. mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret);
        goto exit;
    }
    
    if ((ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type((mbedtls_pk_type_t)MBEDTLS_PK_RSA))) != 0)
    {
        printf("Failed. mbedtls_pk_setup_returned -0x%04x\n", -ret);
        goto exit;
    }
    
    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &ctr_drbg,
                              RSA_KEY_SIZE, 65537);
    if (ret != 0)
    {
        printf("Failed. mbedtls_rsa_gen_key returned -0x%04x\n", -ret);
        goto exit;
    }

    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(key);

    if (mbedtls_rsa_check_pubkey(rsa) != 0)
    {
        printf("RSA context does not contains public key!");
        goto exit;
    }

    if (mbedtls_rsa_check_privkey(rsa) != 0)
    {
        printf("RSA context does not contain private key");
        goto exit;
    }

    unsigned char *pubkey_pem = (unsigned char *)malloc(1024);
    memset(pubkey_pem, 0, 1024);
    if (mbedtls_pk_write_pubkey_pem(&key, pubkey_pem, 1024) != 0)
    {
        printf("Failed writing public key to string.");
        goto exit;
    }
    printf("pubkey len:%d\n",strlen(pubkey_pem));
    printf("pubkey:\n%s\n",pubkey_pem);
    
    FILE *fp = fopen("pubkey.pem","w+");
    fwrite(pubkey_pem,1,strlen(pubkey_pem),fp);
    fclose(fp); 
    free(pubkey_pem);
    
    unsigned char *prikey_pem = (unsigned char *)malloc(2048);
    memset(prikey_pem, 0, 2048);
    if (mbedtls_pk_write_key_pem(&key, prikey_pem, 2048) != 0)
    {
        printf("Failed writing private key to string.");
        goto exit;
    }
    printf("prikey len:%d\n",strlen(prikey_pem));
    printf("privkey:%s\n",prikey_pem);
    
    fp = fopen("prikey.pem","w+");
    fwrite(prikey_pem,1,strlen(prikey_pem),fp);
    fclose(fp);
    free(prikey_pem);
exit:
    mbedtls_pk_free(&key);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return -1;
}

int gen_csr_file()
{
    int ret;
    const char *pers = "gen_csr_file";
    mbedtls_pk_context key;
    mbedtls_x509write_csr req;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    
    mbedtls_pk_init(&key);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509write_csr_init(&req);

    mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);
    
    mbedtls_entropy_init(&entropy);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0)
    {
        printf("Failed. mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret);

        return -1;
    }

    if ((ret = mbedtls_x509write_csr_set_subject_name(&req, DFL_SUBJECT_NAME)) != 0)
    {
        printf("Failed! mbedtls_x509write_csr_set_subject_name returned -0x%04x\n", -ret);
        goto exit;
    }

    FILE * fp = fopen("prikey.pem","r");
    char prikey_buf[2048];
    int n = fread(prikey_buf,1,sizeof(prikey_buf),fp);
    prikey_buf[n] = '\0';
    fclose(fp);
    printf("prikey len %d\n",n);
    printf("read prikey:\n%s\n",prikey_buf);
    
    ret = mbedtls_pk_parse_key(&key,prikey_buf,strlen(prikey_buf) + 1,NULL,0,
              mbedtls_entropy_func,&entropy);
    if(ret != 0)
    {
        printf("Failed! mbedtls_pk_parse_key returned -0x%04x\n", -ret);
        goto exit;
    }

    mbedtls_x509write_csr_set_key(&req, &key);

    unsigned char *csr_pem = (unsigned char *)malloc(4096);
    printf("csr_pem :%p\n",csr_pem);
    memset(csr_pem, 0, 4096);
    if ((ret = mbedtls_x509write_csr_pem(&req, csr_pem, 4096,mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
    {
        printf("Failed! mbedtls_x509write_csr_pem returned -0x%04x\n", -ret);
        //goto exit;
    }

    for (size_t i = 0; i < strlen((char*)csr_pem); i++)
    {
        printf("%c", csr_pem[i]);
    }
    printf("\r\n\r\n");

    fp = fopen("csr.pem","w+");
    fwrite(csr_pem,1,strlen(csr_pem),fp);
    fclose(fp);

    free(csr_pem);
exit:
    mbedtls_x509write_csr_free(&req);
    mbedtls_pk_free(&key);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

int rsa_prikey_decrypt()
{
    int ret;
    const char *pers = "rsa_prikey_decrypt";
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    
    mbedtls_pk_init(&key);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0)
    {
        printf("Failed. mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret);

        goto exit;
    }

    FILE * fp = fopen("prikey.pem","r");
    char prikey_buf[2048];
    int n = fread(prikey_buf,1,sizeof(prikey_buf),fp);
    prikey_buf[n] = '\0';
    fclose(fp);
    printf("prikey len %d\n",n);
    printf("read prikey:\n%s\n",prikey_buf);
    
    ret = mbedtls_pk_parse_key(&key,prikey_buf,strlen(prikey_buf) + 1,NULL,0,
              mbedtls_entropy_func,&entropy);
    if(ret != 0)
    {
        printf("Failed! mbedtls_pk_parse_key returned -0x%04x\n", -ret);
        goto exit;
    }

exit:
    mbedtls_pk_free(&key);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

int main()
{
    gen_rsa_key();
    gen_csr_file();
}

/* int main()
{
    int ret = 1;
    mbedtls_pk_context key;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509write_csr req;
    const char *pers = "gen_key";
    mbedtls_pk_init(&key);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509write_csr_init(&req);

    opt.type = DFL_TYPE;
    opt.rsa_keysize = DFL_RSA_KEYSIZE;
    opt.format = DFL_FORMAT;
    opt.md_alg = DFL_MD_ALG;
    opt.subject_name = DFL_SUBJECT_NAME;

    mbedtls_x509write_csr_set_md_alg(&req, opt.md_alg);

    printf("Seeding the random number generator...\n");

    mbedtls_entropy_init(&entropy);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0)
    {
        printf("Failed. mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret);

        return -1;
    }

    printf("Generating the private key!\n");

    if ((ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type((mbedtls_pk_type_t)opt.type))) != 0)
    {
        printf("Failed. mbedtls_pk_setup_returned -0x%04x\n", -ret);

        return -1;
    }

    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &ctr_drbg,
                              opt.rsa_keysize, 65537);
    if (ret != 0)
    {
        printf("Failed. mbedtls_rsa_gen_key returned -0x%04x\n", -ret);
        return -1;
    }

    printf("OK. Key information:\n");
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(key);

    if (mbedtls_rsa_check_pubkey(rsa) != 0)
    {
        printf("RSA context does not contains public key!");
        goto exit;
    }

    if (mbedtls_rsa_check_privkey(rsa) != 0)
    {
        printf("RSA context does not contain private key");
        goto exit;
    }

    unsigned char *pubkey_pem = (unsigned char *)malloc(1024);
    memset(pubkey_pem, 0, 1024);
    if (mbedtls_pk_write_pubkey_pem(&key, pubkey_pem, 1024) != 0)
    {
        printf("Failed writing public key to string.");
        goto exit;
    }

    for (size_t i = 0; i < strlen((char*)pubkey_pem); i++)
    {
        printf("%c", pubkey_pem[i]);
    }

    free(pubkey_pem);

    printf("\r\n");

    unsigned char *privkey_pem = (unsigned char *)malloc(2048);
    memset(privkey_pem, 0, 2048);
    if (mbedtls_pk_write_key_pem(&key, privkey_pem, 2048) != 0)
    {
        printf("Failed writing private key to string.");
        goto exit;
    }

    fflush(stdout);

    for (size_t i = 0; i < strlen((char*)privkey_pem); i++)
    {
        printf("%c", privkey_pem[i]);
    }
    printf("\r\n");

    free(privkey_pem);

    fflush(stdout);

    printf("OK.\n");

    if ((ret = mbedtls_x509write_csr_set_subject_name(&req, opt.subject_name)) != 0)
    {
        printf("Failed! mbedtls_x509write_csr_set_subject_name returned -0x%04x\n", -ret);
        goto exit;
    }

    mbedtls_x509write_csr_set_key(&req, &key);

    //unsigned char *csr_pem = (unsigned char *)malloc(4096);
    char *csr_pem;
    //printf("csr_pem :%p\n",csr_pem);
    //memset(csr_pem, 0, 4096);
    if ((ret = mbedtls_x509write_csr_pem(&req, csr_pem, 4096, NULL, NULL)) != 0)
    {
        printf("Failed! mbedtls_x509write_csr_pem returned -0x%04x\n", -ret);
        //goto exit;
    }

    for (size_t i = 0; i < strlen((char*)csr_pem); i++)
    {
        printf("%c", csr_pem[i]);
    }
    printf("\r\n\r\n");

    free(csr_pem);

cleanup:
    mbedtls_x509write_csr_free(&req);
    mbedtls_pk_free(&key);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

} */