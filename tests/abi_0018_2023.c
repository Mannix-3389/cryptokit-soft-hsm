/* Compile this file against the distributed SDK headers to guard the
 * GM/T 0018-2023 6.5.6 and 6.8 function signatures. */
#include "sdf.h"

SDFX_STATIC_ASSERT(sizeof(ECCCipher) == offsetof(ECCCipher, C),
                   "ECCCipher flexible data must start at the structure end");
SDFX_STATIC_ASSERT(sizeof(SM9Cipher) == offsetof(SM9Cipher, C),
                   "SM9Cipher flexible data must start at the structure end");

static LONG (*auth_dec)(HANDLE, HANDLE, ULONG, BYTE *, ULONG, BYTE *, ULONG,
                        BYTE *, ULONG *, BYTE *, ULONG, BYTE *, ULONG *) = SDF_AuthDec;
static LONG (*rsa_pair)(ULONG, RSArefPublicKey *, RSArefPrivateKey *) = SDF_GenerateKeyPair_RSA;
static LONG (*ecc_pair)(ULONG, ULONG, ECCrefPublicKey *, ECCrefPrivateKey *) = SDF_GenerateKeyPair_ECC;
static LONG (*rsa_private)(RSArefPrivateKey *, BYTE *, ULONG, BYTE *, ULONG *) = SDF_ExternalPrivateKeyOperation_RSA;
static LONG (*ecc_sign)(ULONG, ECCrefPrivateKey *, BYTE *, ULONG, ECCSignature *) = SDF_ExternalSign_ECC;
static LONG (*ecc_decrypt)(ULONG, ECCrefPrivateKey *, ECCCipher *, BYTE *, ULONG) = SDF_ExternalDecrypt_ECC;
static int (*sm9_sign)(SM9SignMasterPublicKey *, SM9SignUserPrivateKey *, BYTE *, ULONG,
                       SM9Signature *) = SDF_ExternalSign_SM9;
static int (*sm9_decrypt)(SM9EncUserPrivateKey *, BYTE *, ULONG, BYTE *, BYTE *,
                          ULONG, SM9Cipher *) = SDF_ExternalDecrypt_SM9;
static LONG (*external_encrypt)(ULONG, BYTE *, ULONG, BYTE *, ULONG, BYTE *, ULONG,
                                BYTE *, ULONG *) = SDF_ExternalKeyEncrypt;
static LONG (*external_decrypt)(ULONG, BYTE *, ULONG, BYTE *, ULONG, BYTE *, ULONG,
                                BYTE *, ULONG *) = SDF_ExternalKeyDecrypt;

int main(void)
{
    return !(auth_dec && rsa_pair && ecc_pair && rsa_private && ecc_sign &&
             ecc_decrypt && sm9_sign && sm9_decrypt && external_encrypt &&
             external_decrypt);
}
