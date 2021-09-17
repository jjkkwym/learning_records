#include <stdio.h>
#include <string.h>
#include <tee_internal_api.h>
#include <rsa_ta.h>
#include "rsa_crypto.h"
#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha1.h"
#include "mbedtls/platform.h"
#include "mbedtls/config.h"
#include "mbedtls/oid.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/error.h"
#include <string.h>
#include "mbedtls/md.h"
#include "mbedtls/entropy.h"
#include "mbedtls/bignum.h"


#define RSA_KEY_SIZE 1024
#define MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)


char *strstr (const char *s1, const char *s2)
{
  const char *p = s1;
  const size_t len = strlen (s2);
  for (; (p = strchr (p, *s2)) != 0; p++)
    {
      if (strncmp (p, s2, len) == 0)
        return (char *)p;
    }
  return (0);
}

char* strncpy(char* destination, const char* source, unsigned int num)
{
    char* ptr = NULL;
	// return if no memory is allocated to the destination
    // if (destination == NULL) {
    //     return NULL;
    // }
 
    // take a pointer pointing to the beginning of the destination string
    ptr = destination;
 
    // copy first `num` characters of C-string pointed by source
    // into the array pointed by destination
    while (*source && num--)
    {
        *destination = *source;
        destination++;
        source++;
    }
 
    // null terminate destination string
    *destination = '\0';
 
    // the destination is returned by standard `strncpy()`
    return ptr;
}

#define FORMAT_PEM 0
#define FORMAT_DER 1

#define DFL_TYPE MBEDTLS_PK_RSA
#define DFL_RSA_KEYSIZE 2048
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

static void dump_buf(char *info, uint8_t *buf, uint32_t len)
{
    mbedtls_printf("%s", info);
    for (int i = 0; i < len; i++) {
        mbedtls_printf("%s%02X%s", i % 16 == 0 ? "\n     ":" ", 
                        buf[i], i == len - 1 ? "\n":"");
    }
}

static void test(void)
{
    int ret = 1;
    mbedtls_pk_context key;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509write_csr req;
    //const char *pers = "gen_key";
	mbedtls_rsa_context *rsa;
	unsigned char *pubkey_pem;
	unsigned int i = 0;
	unsigned char *csr_pem;
	unsigned char *privkey_pem;

    mbedtls_pk_init(&key);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509write_csr_init(&req);

    opt.type = DFL_TYPE;
    opt.rsa_keysize = DFL_RSA_KEYSIZE;
    opt.format = DFL_FORMAT;
    opt.md_alg = DFL_MD_ALG;
    opt.subject_name = DFL_SUBJECT_NAME;

	printf("Hello world!");
    mbedtls_x509write_csr_set_md_alg(&req, opt.md_alg);

    printf("Seeding the random number generator...");

    //mbedtls_entropy_init(&entropy);

/*     if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0)
    {
        printf("Failed. mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret);

        //return;
    } */

    printf("Generating the private key!");

    if ((ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type((mbedtls_pk_type_t)opt.type))) != 0)
    {
        printf("Failed. mbedtls_pk_setup_returned -0x%04x", -ret);

        return;
    }

    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &ctr_drbg,
                              opt.rsa_keysize, 65537);
    if (ret != 0)
    {
        printf("Failed. mbedtls_rsa_gen_key returned -0x%04x", -ret);
        return;
    }

    printf("OK. Key information:");

    rsa = mbedtls_pk_rsa(key);

    if (mbedtls_rsa_check_pubkey(rsa) != 0)
    {
        printf("RSA context does not contains public key!");
        goto cleanup;
    }

    if (mbedtls_rsa_check_privkey(rsa) != 0)
    {
        printf("RSA context does not contain private key");
        goto cleanup;
    }

    pubkey_pem = (unsigned char *)malloc(1024);
    memset(pubkey_pem, 0, 1024);
    if (mbedtls_pk_write_pubkey_pem(&key, pubkey_pem, 1024) != 0)
    {
        printf("Failed writing public key to string.");
        goto cleanup;
    }

    for (i = 0; i < strlen((char*)pubkey_pem); i++)
    {
        printf("%c", pubkey_pem[i]);
    }

    free(pubkey_pem);

    printf("\r\n");

    privkey_pem = (unsigned char *)malloc(2048);
    memset(privkey_pem, 0, 2048);
    if (mbedtls_pk_write_key_pem(&key, privkey_pem, 2048) != 0)
    {
        printf("Failed writing private key to string.");
        goto cleanup;
    }

    for (i = 0; i < strlen((char*)privkey_pem); i++)
    {
        printf("%c", privkey_pem[i]);
    }
    printf("\r\n");

    free(privkey_pem);

    printf("OK.\n");

    if ((ret = mbedtls_x509write_csr_set_subject_name(&req, opt.subject_name)) != 0)
    {
        printf("Failed! mbedtls_x509write_csr_set_subject_name returned -0x%04x", -ret);
        goto cleanup;
    }

    mbedtls_x509write_csr_set_key(&req, &key);

    csr_pem = (unsigned char *)malloc(4096);
    memset(csr_pem, 0, 4096);
    if ((ret = mbedtls_x509write_csr_pem(&req, csr_pem, 4096, NULL, NULL)) != 0)
    {
        printf("Failed! mbedtls_x509write_csr_pem returned -0x%04x", -ret);
        goto cleanup;
    }

    for (i = 0; i < strlen((char*)csr_pem); i++)
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
}



struct rsa_session {
	TEE_OperationHandle op_handle;	/* RSA operation */
	TEE_ObjectHandle key_handle; /* Key handle */
};

static TEE_Result prepare_rsa_operation(TEE_OperationHandle *handle, uint32_t alg, TEE_OperationMode mode, TEE_ObjectHandle key) {
	TEE_Result ret = TEE_SUCCESS;	
	TEE_ObjectInfo key_info;
	ret = TEE_GetObjectInfo1(key, &key_info);
	if (ret != TEE_SUCCESS) {
		//EMSG("\nTEE_GetObjectInfo1: %#\n" PRIx32, ret);
		return ret;
	}

	ret = TEE_AllocateOperation(handle, alg, mode, key_info.keySize);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc operation handle : 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Operation allocated successfully. ==========\n");

	ret = TEE_SetOperationKey(*handle, key);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to set key : 0x%x\n", ret);
		return ret;
	}
    DMSG("\n========== Operation key already set. ==========\n");

	return ret;
}

static TEE_Result check_params(uint32_t param_types) {
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	return TEE_SUCCESS;
}

static TEE_Result RSA_create_key_pair(void *session) {

	TEE_Result ret;
	size_t key_size = RSA_KEY_SIZE;
	struct rsa_session *sess = (struct rsa_session *)session;
	
	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc transient object handle: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Transient object allocated. ==========\n");

	ret = TEE_GenerateKey(sess->key_handle, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		EMSG("\nGenerate key failure: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Keys generated. ==========\n");
	return ret;
}

static TEE_Result RSA_encrypt(void *session, uint32_t param_types, TEE_Param params[4]) {
	TEE_Result ret;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	struct rsa_session *sess = (struct rsa_session *)session;


	void *plain_txt = params[0].memref.buffer;
	size_t plain_len = params[0].memref.size;
	void *cipher = params[1].memref.buffer;
	size_t cipher_len = params[1].memref.size;

	if (check_params(param_types) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;
	DMSG("\n========== Preparing encryption operation ==========\n");
	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_ENCRYPT, sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to prepare RSA operation: 0x%x\n", ret);
		goto err;
	}

	DMSG("\nData to encrypt: %s\n", (char *) plain_txt);
	ret = TEE_AsymmetricEncrypt(sess->op_handle, (TEE_Attribute *)NULL, 0,
					plain_txt, plain_len, cipher, &cipher_len);					
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to encrypt the passed buffer: 0x%x\n", ret);
		goto err;
	}
	DMSG("\nEncrypted data: %s\n", (char *) cipher);
	DMSG("\n========== Encryption successfully ==========\n");
	return ret;

err:
	TEE_FreeOperation(sess->op_handle);
	TEE_FreeTransientObject(sess->key_handle);
	return ret;
}

static TEE_Result RSA_decrypt(void *session, uint32_t param_types, TEE_Param params[4]) {
	TEE_Result ret;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	struct rsa_session *sess = (struct rsa_session *)session;

	void *plain_txt = params[1].memref.buffer;
	size_t plain_len = params[1].memref.size;
	void *cipher = params[0].memref.buffer;
	size_t cipher_len = params[0].memref.size;

	if (check_params(param_types) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;


	DMSG("\n========== Preparing decryption operation ==========\n");
	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_DECRYPT, sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to prepare RSA operation: 0x%x\n", ret);
		goto err;
	}

	DMSG("\nData to decrypt: %s\n", (char *) cipher);
	ret = TEE_AsymmetricDecrypt(sess->op_handle, (TEE_Attribute *)NULL, 0,
				cipher, cipher_len, plain_txt, &plain_len);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to decrypt the passed buffer: 0x%x\n", ret);
		goto err;
	}
	DMSG("\nDecrypted data: %s\n", (char *) plain_txt);
	DMSG("\n========== Decryption successfully ==========\n");
	return ret;

err:
	TEE_FreeOperation(sess->op_handle);
	TEE_FreeTransientObject(sess->key_handle);
	return ret;
}

TEE_Result TA_CreateEntryPoint(void) {
	/* Nothing to do */
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
	/* Nothing to do */
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
					TEE_Param __unused params[4],
					void __unused **session) {
	struct rsa_session *sess;
	sess = TEE_Malloc(sizeof(*sess), 0);
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;

	*session = (void *)sess;
	DMSG("\nSession %p: newly allocated\n", *session);

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
	struct rsa_session *sess;

	/* Get ciphering context from session ID */
	DMSG("Session %p: release session", session);
	sess = (struct rsa_session *)session;

	/* Release the session resources
	   These tests are mandatories to avoid PANIC TA (TEE_HANDLE_NULL) */
	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);
	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);
	TEE_Free(sess);
}

TEE_Result TA_InvokeCommandEntryPoint(void *session,
					uint32_t cmd,
					uint32_t param_types,
					TEE_Param params[4]) {
	switch (cmd) {
		case TA_RSA_CMD_GENKEYS:
			test();
			return RSA_create_key_pair(session);
		case TA_RSA_CMD_ENCRYPT:
			return RSA_encrypt(session, param_types, params);
		case TA_RSA_CMD_DECRYPT:
			return RSA_decrypt(session, param_types, params);
		default:
			EMSG("Command ID 0x%x is not supported", cmd);
			return TEE_ERROR_NOT_SUPPORTED;
	}
}
