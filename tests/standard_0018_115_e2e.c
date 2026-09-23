/* Windows SDK smoke test for the GM/T 0018-2023 stateless 6.8 ABI. */
#include <stdio.h>
#include <string.h>
#include "sdf.h"

#define REQUIRE(expr) do { \
    LONG result = (expr); \
    if (result != SDR_OK) { \
        fprintf(stderr, "%s: 0x%08x\n", #expr, (unsigned)result); \
        failed = 1; \
        goto cleanup; \
    } \
} while (0)

int main(void)
{
    int failed = 0;
    HANDLE device = NULL, session = NULL;
    RSArefPublicKey rsa_public;
    RSArefPrivateKey rsa_private;
    ECCrefPublicKey ecc_public;
    ECCrefPrivateKey ecc_private;
    ECCSignature signature;
    BYTE representative[RSAref_MAX_LEN] = {0};
    BYTE rsa_output[RSAref_MAX_LEN] = {0};
    BYTE digest[32] = {1};
    BYTE message[16] = "0018-2023-smoke";
    BYTE ecc_storage[sizeof(ECCCipher) + sizeof(message)];
    ECCCipher *ecc_cipher = (ECCCipher *)ecc_storage;
    BYTE recovered[32] = {0};
    BYTE key[16] = {0}, iv[16] = {0};
    BYTE encrypted[32] = {0};
    ULONG rsa_length = sizeof(rsa_output);
    ULONG encrypted_length = sizeof(encrypted);
    ULONG recovered_length = sizeof(recovered);

    representative[sizeof(representative) - 1] = 2;
    REQUIRE(SDF_OpenDevice(&device));
    REQUIRE(SDF_OpenSession(device, &session));
    REQUIRE(SDF_GenerateKeyPair_RSA(2048, &rsa_public, &rsa_private));
    REQUIRE(SDF_ExternalPrivateKeyOperation_RSA(&rsa_private, representative,
        sizeof(representative), rsa_output, &rsa_length));
    REQUIRE(SDF_GenerateKeyPair_ECC(SGD_SM2_3, 256, &ecc_public, &ecc_private));
    REQUIRE(SDF_ExternalSign_ECC(SGD_SM2_1, &ecc_private, digest,
        sizeof(digest), &signature));
    REQUIRE(SDF_ExternalVerify_ECC(session, SGD_SM2_1, &ecc_public, digest,
        sizeof(digest), &signature));
    REQUIRE(SDF_ExternalEncrypt_ECC(session, SGD_SM2_3, &ecc_public, message,
        sizeof(message), ecc_cipher));
    REQUIRE(SDF_ExternalDecrypt_ECC(SGD_SM2_3, &ecc_private, ecc_cipher,
        recovered, sizeof(recovered)));
    if (memcmp(recovered, message, sizeof(message)) != 0) {
        fprintf(stderr, "SM2 decrypt mismatch\n");
        failed = 1;
        goto cleanup;
    }
    REQUIRE(SDF_ExternalKeyEncrypt(SGD_SM4_CBC, key, sizeof(key), iv,
        sizeof(iv), message, sizeof(message), encrypted, &encrypted_length));
    REQUIRE(SDF_ExternalKeyDecrypt(SGD_SM4_CBC, key, sizeof(key), iv,
        sizeof(iv), encrypted, encrypted_length, recovered, &recovered_length));
    if (recovered_length != sizeof(message) ||
        memcmp(recovered, message, sizeof(message)) != 0) {
        fprintf(stderr, "SM4 decrypt mismatch\n");
        failed = 1;
    }

cleanup:
    if (session != NULL) SDF_CloseSession(session);
    if (device != NULL) SDF_CloseDevice(device);
    if (!failed) puts("GM/T 0018-2023 1.1.5 SDK smoke test passed");
    return failed;
}
