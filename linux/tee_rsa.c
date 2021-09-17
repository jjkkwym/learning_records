#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

void test_sign_verify(void);

void test_sign_verify(void)
{
    uint32_t keySize = 1024;
    TEE_Result res = TEE_SUCCESS;
    TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
    TEE_OperationHandle op_handle = TEE_HANDLE_NULL;

    uint8_t signature[256];
    uint32_t signatureLen = sizeof(signature);
    uint8_t digest[20];
    uint32_t digestLen = 20;
    uint8_t modulus[258];
    uint32_t modulusLen = sizeof(modulus);
    uint8_t pubexp[258];
    uint32_t pubexpLen = sizeof(modulus);
    uint8_t pvtexp[258];
    uint32_t pvtexpLen = sizeof(modulus);
    TEE_Attribute attrs[3];

    /* Generate RSA key pair */
    TEE_GenerateRandom(digest, sizeof(digest));
    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, keySize, &key_handle);
    if (res != TEE_SUCCESS)
    {
        DMSG("TEE_AllocateTransientObject() failed res=0x%X\n", (int)res);
        goto exit;
    }
    res = TEE_GenerateKey(key_handle, keySize, NULL, 0);
    if (res != TEE_SUCCESS)
    {
        DMSG("TEE_GenerateKey() failed res=0x%X\n", (int)res);
        goto exit;
    }

    /* RSA sign */
    res = TEE_AllocateOperation(&op_handle, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_SIGN, keySize);
    if (res != TEE_SUCCESS)
    {
        DMSG("TEE_AllocateOperation() failed res=0x%X\n", (int)res);
        goto exit;
    }
    res = TEE_SetOperationKey(op_handle, key_handle);
    if (res != TEE_SUCCESS)
    {
        DMSG("TEE_SetOperationKey() failed res=0x%X\n", (int)res);
        goto exit;
    }
    res = TEE_AsymmetricSignDigest(op_handle, NULL, 0, (void *)digest, digestLen, (void *)signature, &signatureLen);
    if (res != TEE_SUCCESS)
    {
        DMSG("TEE_AsymmetricSignDigest() failed res=0x%X\n", (int)res);
        goto exit;
    }
    TEE_FreeOperation(op_handle);
    op_handle = TEE_HANDLE_NULL;
    DMSG("[OK] SignDigest, signatureLen=%d\n", (int)signatureLen);

    /* RSA verify */
    res = TEE_AllocateOperation(&op_handle, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_VERIFY, keySize);
    if (res != TEE_SUCCESS)
    {
        DMSG("TEE_SetOperationKey() failed res=0x%X\n", (int)res);
        goto exit;
    }
    res = TEE_SetOperationKey(op_handle, key_handle);
    if (res != TEE_SUCCESS)
    {
        DMSG("TEE_SetOperationKey() failed res=0x%X\n", (int)res);
        goto exit;
    }
    res = TEE_AsymmetricVerifyDigest(op_handle, NULL, 0, (void *)digest, digestLen, (void *)signature, signatureLen);
    DMSG("[%s] VerifyDigest\n", (res == 0) ? "OK" : "FAILED");
    if (res != TEE_SUCCESS)
    {
        goto exit;
    }
    TEE_FreeOperation(op_handle);
    op_handle = TEE_HANDLE_NULL;

    /* Export private key */
    res = TEE_GetObjectBufferAttribute(key_handle, TEE_ATTR_RSA_MODULUS, (void *)modulus, &modulusLen);
    if (res != TEE_SUCCESS)
    {
        DMSG("TEE_GetObjectBufferAttribute() failed res=0x%X\n", (int)res);
        goto exit;
    }
    res = TEE_GetObjectBufferAttribute(key_handle, TEE_ATTR_RSA_PUBLIC_EXPONENT, (void *)pubexp, &pubexpLen);
    if (res != TEE_SUCCESS)
    {
        DMSG("TEE_GetObjectBufferAttribute() failed res=0x%X\n", (int)res);
        goto exit;
    }
    res = TEE_GetObjectBufferAttribute(key_handle, TEE_ATTR_RSA_PRIVATE_EXPONENT, (void *)pvtexp, &pvtexpLen);
    if (res != TEE_SUCCESS)
    {
        DMSG("TEE_GetObjectBufferAttribute() failed res=0x%X\n", (int)res);
        goto exit;
    }
    DMSG("RSA_MODULUS %d bytes\n", (int)modulusLen);
    DMSG("RSA_PUBLIC_EXPONENT %d bytes\n", (int)pubexpLen);
    DMSG("RSA_PRIVATE_EXPONENT %d bytes\n", (int)pvtexpLen);
    DMSG("[%s] Export private key\n", (res == 0) ? "OK" : "FAILED");

    /* Import private key */
    TEE_FreeTransientObject(key_handle);
    key_handle = TEE_HANDLE_NULL;

    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, keySize, &key_handle); /* TEE_TYPE_RSA_PUBLIC_KEY */
    if (res != TEE_SUCCESS)
    {
        DMSG("TEE_AllocateTransientObject() failed res=0x%X\n", (int)res);
        goto exit;
    }
    TEE_MemFill(attrs, 0, sizeof(attrs));

    TEE_InitRefAttribute(&attrs[0], TEE_ATTR_RSA_MODULUS, modulus, modulusLen);
    TEE_InitRefAttribute(&attrs[1], TEE_ATTR_RSA_PUBLIC_EXPONENT, pubexp, pubexpLen);
    TEE_InitRefAttribute(&attrs[2], TEE_ATTR_RSA_PRIVATE_EXPONENT, pvtexp, pvtexpLen);
    res = TEE_PopulateTransientObject(key_handle, attrs, 3);
    if (res != TEE_SUCCESS)
    {
        DMSG("TEE_PopulateTransientObject() failed res=0x%X\n", (int)res);
        goto exit;
    }
    DMSG("[%s] Import private key\n", (res == 0) ? "OK" : "FAILED");

    /* RSA sign */
    signatureLen = sizeof(signature);
    res = TEE_AllocateOperation(&op_handle, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_SIGN, keySize);
    if (res != TEE_SUCCESS)
    {
        DMSG("TEE_AllocateOperation() failed res=0x%X\n", (int)res);
        goto exit;
    }
    res = TEE_SetOperationKey(op_handle, key_handle);
    if (res != TEE_SUCCESS)
    {
        DMSG("TEE_SetOperationKey() failed res=0x%X\n", (int)res);
        goto exit;
    }
    res = TEE_AsymmetricSignDigest(op_handle, NULL, 0, (void *)digest, digestLen, (void *)signature, &signatureLen);
    if (res != TEE_SUCCESS)
    {
        DMSG("TEE_AsymmetricSignDigest() failed res=0x%X\n", (int)res);
        goto exit;
    }
    TEE_FreeOperation(op_handle);
    op_handle = TEE_HANDLE_NULL;
    DMSG("[OK] SignDigest, signatureLen=%d\n", (int)signatureLen);

    /* RSA verify */
    res = TEE_AllocateOperation(&op_handle, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_VERIFY, keySize);
    if (res != TEE_SUCCESS)
    {
        DMSG("TEE_SetOperationKey() failed res=0x%X\n", (int)res);
        goto exit;
    }
    res = TEE_SetOperationKey(op_handle, key_handle);
    if (res != TEE_SUCCESS)
    {
        DMSG("TEE_SetOperationKey() failed res=0x%X\n", (int)res);
        goto exit;
    }
    res = TEE_AsymmetricVerifyDigest(op_handle, NULL, 0, (void *)digest, digestLen, (void *)signature, signatureLen);
    DMSG("[%s] VerifyDigest   res=0x%X\n", (res == 0) ? "OK" : "FAILED", (int)res);
    if (res != TEE_SUCCESS)
    {
        goto exit;
    }

exit:
    if (op_handle != TEE_HANDLE_NULL)
    {
        TEE_FreeOperation(op_handle);
    }
    if (key_handle != TEE_HANDLE_NULL)
    {
        TEE_FreeTransientObject(key_handle);
    }
}