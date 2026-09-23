#ifndef __SDF_TYPES_H__
#define __SDF_TYPES_H__
#include <stdint.h>
#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif

/* 5.2 基本数据类型定义 (Basic Data Type Definitions) */
#ifdef _WIN32
# include <windows.h>
typedef uint32_t FLAGS;
#else
typedef unsigned char BYTE;
typedef unsigned char CHAR;
typedef int32_t LONG;
typedef uint32_t ULONG;
typedef uint32_t FLAGS;
typedef CHAR *LPSTR;
typedef void *HANDLE;
#endif

#define SDFX_CONCAT_INNER(a, b) a##b
#define SDFX_CONCAT(a, b) SDFX_CONCAT_INNER(a, b)

#if defined(__cplusplus)
# define SDFX_STATIC_ASSERT(condition, message) static_assert(condition, message)
#elif defined(_MSC_VER) && !defined(__clang__)
/*
 * MSVC accepts C sources without /std:c11 by default. In that mode
 * _Static_assert is not available, so use a file-scope typedef assertion.
 */
# define SDFX_STATIC_ASSERT(condition, message) \
    typedef char SDFX_CONCAT(sdfx_static_assert_, __LINE__)[(condition) ? 1 : -1]
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
# define SDFX_STATIC_ASSERT(condition, message) _Static_assert(condition, message)
#else
# define SDFX_STATIC_ASSERT(condition, message) \
    typedef char SDFX_CONCAT(sdfx_static_assert_, __LINE__)[(condition) ? 1 : -1]
#endif

SDFX_STATIC_ASSERT(sizeof(LONG) == 4, "LONG must be 32-bit");
SDFX_STATIC_ASSERT(sizeof(ULONG) == 4, "ULONG must be 32-bit");

/* 5.3 设备信息定义 (Device Info Definition) */
typedef struct DeviceInfo_st
{
    CHAR  IssuerName[40];
    CHAR  DeviceName[16];
    CHAR  DeviceSerial[16];
    ULONG DeviceVersion;
    ULONG StandardVersion;
    ULONG AsymAlgAbility[2];
    ULONG SymAlgAbility;
    ULONG HashAlgAbility;
    ULONG BufferSize;
} DEVICEINFO;

/* 5.4 算法标识符定义 (Algorithm Identifier Definitions) */
/*
 * 算法标识符编码规则（32位）：
 * - 高16位：算法类型
 * - 低16位：算法模式或变体
 */

/* 对称算法 (Symmetric Algorithms) */
/* SM1 算法 (0x0001xxxx) */
#define SGD_SM1_ECB                 0x00000101   /* SM1 algorithm ECB mode */
#define SGD_SM1_CBC                 0x00000102   /* SM1 algorithm CBC mode */
#define SGD_SM1_CFB                 0x00000104   /* SM1 algorithm CFB mode */
#define SGD_SM1_OFB                 0x00000108   /* SM1 algorithm OFB mode */
#define SGD_SM1_MAC                 0x00000110   /* SM1 algorithm MAC mode */

/* SSF33 算法 (0x0002xxxx) */
#define SGD_SSF33_ECB               0x00000201   /* SSF33 algorithm ECB mode */
#define SGD_SSF33_CBC               0x00000202   /* SSF33 algorithm CBC mode */
#define SGD_SSF33_CFB               0x00000204   /* SSF33 algorithm CFB mode */
#define SGD_SSF33_OFB               0x00000208   /* SSF33 algorithm OFB mode */
#define SGD_SSF33_MAC               0x00000210   /* SSF33 algorithm MAC mode */

/* SMS4(SM4) 算法（标识值遵循 GM/T 0006-2023） */
#define SGD_SM4_ECB                 0x00000401   /* SM4 algorithm ECB mode */
#define SGD_SM4_CBC                 0x00000402   /* SM4 algorithm CBC mode */
#define SGD_SM4_CFB                 0x00000404   /* SM4 algorithm CFB mode */
#define SGD_SM4_OFB                 0x00000408   /* SM4 algorithm OFB mode */
#define SGD_SM4_MAC                 0x00000410   /* SM4 algorithm MAC mode */
#define SGD_SM4_GCM                 0x02000400   /* SM4 algorithm GCM mode */
#define SGD_SM4_CCM                 0x04000400   /* SM4 algorithm CCM mode */
#define SGD_SM4_XTS                 0x01000400   /* SM4 algorithm XTS mode */
#define SGD_SM4_CTR                 0x00000420   /* SM4 algorithm CTR mode (SGD_SM4 | SGD_CTR) */

/* 非对称算法 (Asymmetric Algorithms) */
/* RSA 算法 (0x0001xxxx) */
#define SGD_RSA                     0x00010000   /* RSA algorithm */

/* SM2 算法 (0x0002xxxx) */
#define SGD_SM2                     0x00020100   /* SM2 elliptic curve cryptographic algorithm */
#define SGD_SM2_1                   0x00020200   /* SM2 elliptic curve sign algorithm */
#define SGD_SM2_2                   0x00020400   /* SM2 elliptic curve key exchange protocol */
#define SGD_SM2_3                   0x00020800   /* SM2 elliptic curve encryption algorithm */

/* GM/T 0006-2023 标准杂凑及 HMAC 算法标识 */
#define SGD_SM3                     0x00000001   /* SM3 cryptographic hash algorithm */
#define SGD_SHA256                  0x00000004   /* SHA256 hash algorithm */
#define SGD_SM3_HMAC                0x00000008   /* HMAC-SM3 algorithm */
#define SGD_SHA256_HMAC             0x00000010   /* HMAC-SHA256 algorithm */

/*
 * SDFX 教学扩展杂凑标识。
 * GM/T 0006-2023 将 0x00000020～0x000000FF 预留给自定义杂凑算法。
 * 这些标识不是 GM/T 0006 标准算法标识，不写入标准设备能力字段。
 */
#define SDFX_SHA1                   0x00000020
#define SDFX_SHA224                 0x00000021
#define SDFX_SHA384                 0x00000022
#define SDFX_SHA512                 0x00000023
#define SDFX_SHA512_224             0x00000024   /* identifier reserved; implementation unavailable */
#define SDFX_SHA512_256             0x00000025   /* identifier reserved; implementation unavailable */

/* Deprecated source-compatibility aliases for pre-1.1.5 teaching programs. */
#define SGD_SHA1                    SDFX_SHA1
#define SGD_SHA224                  SDFX_SHA224
#define SGD_SHA384                  SDFX_SHA384
#define SGD_SHA512                  SDFX_SHA512
#define SGD_SHA512_224              SDFX_SHA512_224
#define SGD_SHA512_256              SDFX_SHA512_256

/* Catch accidental protocol regressions at compile time. */
SDFX_STATIC_ASSERT(SGD_SM4_XTS == 0x01000400, "GM/T 0006 SM4-XTS identifier mismatch");
SDFX_STATIC_ASSERT(SGD_SM2 == 0x00020100, "GM/T 0006 SM2 identifier mismatch");
SDFX_STATIC_ASSERT(SGD_SM2_1 == 0x00020200, "GM/T 0006 SM2 sign identifier mismatch");
SDFX_STATIC_ASSERT(SGD_SM2_2 == 0x00020400, "GM/T 0006 SM2 agreement identifier mismatch");
SDFX_STATIC_ASSERT(SGD_SM2_3 == 0x00020800, "GM/T 0006 SM2 encryption identifier mismatch");
SDFX_STATIC_ASSERT(SGD_SM3_HMAC == 0x00000008, "GM/T 0006 HMAC-SM3 identifier mismatch");
SDFX_STATIC_ASSERT(SGD_SHA256_HMAC == 0x00000010, "GM/T 0006 HMAC-SHA256 identifier mismatch");

/* SM9 算法 (0x0008xxxx) */
#define SGD_SM9_1                   0x00080100   /* SM9 identity-based sign algorithm */
#define SGD_SM9_2                   0x00080200   /* SM9 identity-based key exchange protocol */
#define SGD_SM9_3                   0x00080400   /* SM9 identity-based encryption algorithm */

/* 5.5 RSA密钥数据结构定义 (RSA Key Data Structure Definitions) */
#define RSAref_MAX_BITS     2048
#define RSAref_MAX_LEN      ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS    ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN     ((RSAref_MAX_PBITS + 7) / 8)

typedef struct RSArefPublicKey_st
{
    ULONG bits;
    BYTE  m[RSAref_MAX_LEN];
    BYTE  e[RSAref_MAX_LEN];
} RSArefPublicKey;

typedef struct RSArefPrivateKey_st
{
    ULONG bits;
    BYTE  m[RSAref_MAX_LEN];
    BYTE  e[RSAref_MAX_LEN];
    BYTE  d[RSAref_MAX_LEN];
    BYTE  prime[2][RSAref_MAX_PLEN];
    BYTE  pexp[2][RSAref_MAX_PLEN];
    BYTE  coef[RSAref_MAX_PLEN];
} RSArefPrivateKey;

/* 5.6 ECC 密钥数据结构定义 (ECC Key Data Structure Definitions) */
#define ECCref_MAX_BITS     512
#define ECCref_MAX_LEN      ((ECCref_MAX_BITS + 7) / 8)

typedef struct ECCrefPublicKey_st
{
    ULONG bits;
    BYTE  x[ECCref_MAX_LEN];
    BYTE  y[ECCref_MAX_LEN];
} ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st
{
    ULONG bits;
    BYTE  K[ECCref_MAX_LEN];
} ECCrefPrivateKey;

/* 5.7 ECC 加密数据结构定义 (ECC Ciphertext Structure Definition) */
#if defined(_MSC_VER)
# pragma warning(push)
# pragma warning(disable: 4200) /* GM/T 0018-2023 specifies BYTE C[] */
#endif
typedef struct ECCCipher_st
{
    BYTE  x[ECCref_MAX_LEN];
    BYTE  y[ECCref_MAX_LEN];
    BYTE  M[32];
    ULONG L;
    BYTE  C[];
} ECCCipher;
#if defined(_MSC_VER)
# pragma warning(pop)
#endif

/* 5.8 ECC 签名数据结构定义 (ECC Signature Structure Definition) */
typedef struct ECCSignature_st
{
    BYTE r[ECCref_MAX_LEN];
    BYTE s[ECCref_MAX_LEN];
} ECCSignature;

/* 5.9 ECC 密钥对保护结构定义 (ECC Key Pair Protection Structure Definition) */
typedef struct EnvelopedECCKey_st
{
    ULONG           Version;
    ULONG           ulSymmAlgID;
    ULONG           ulBits;
    BYTE            cbEncryptedPriKey[ECCref_MAX_LEN];
    ECCrefPublicKey PubKey;
    ECCCipher       ECCCipherBlob; // 注意: ECCCipher 结构体本身是变长的
} EnvelopedECCKey;


/* 附录 B.1 SM9算法相关数据结构 (SM9 Algorithm Data Structures) */
#define SM9ref_MAX_BITS     256
#define SM9ref_MAX_LEN      ((SM9ref_MAX_BITS + 7) / 8)

/* B.1.1 SM9 主私钥 (SM9 Master Private Key) */
typedef struct SM9refMasterPrivateKey_st
{
    ULONG bits;
    BYTE  s[SM9ref_MAX_LEN];
} SM9MasterPrivateKey;

/* B.1.2 SM9 签名主公钥 (SM9 Sign Master Public Key) */
typedef struct SM9refSignMasterPublicKey_st
{
    ULONG bits;
    BYTE  xa[SM9ref_MAX_LEN];
    BYTE  xb[SM9ref_MAX_LEN];
    BYTE  ya[SM9ref_MAX_LEN];
    BYTE  yb[SM9ref_MAX_LEN];
} SM9SignMasterPublicKey;

/* B.1.3 SM9 加密主公钥 (SM9 Encrypt Master Public Key) */
typedef struct SM9refEncMasterPublicKey_st
{
    ULONG bits;
    BYTE  x[SM9ref_MAX_LEN];
    BYTE  y[SM9ref_MAX_LEN];
} SM9EncMasterPublicKey;

/* B.1.4 SM9 用户签名私钥 (SM9 User Sign Private Key) */
typedef struct SM9refSignUserPrivateKey_st
{
    ULONG bits;
    BYTE  x[SM9ref_MAX_LEN];
    BYTE  y[SM9ref_MAX_LEN];
} SM9SignUserPrivateKey;

/* B.1.5 SM9 用户加密私钥 (SM9 User Encrypt Private Key) */
typedef struct SM9refEncUserPrivateKey_st
{
    ULONG bits;
    BYTE  xa[SM9ref_MAX_LEN];
    BYTE  xb[SM9ref_MAX_LEN];
    BYTE  ya[SM9ref_MAX_LEN];
    BYTE  yb[SM9ref_MAX_LEN];
} SM9EncUserPrivateKey;

/* B.1.6 SM9 加密数据结构 (SM9 Ciphertext Structure) */
#if defined(_MSC_VER)
# pragma warning(push)
# pragma warning(disable: 4200) /* GM/T 0018-2023 specifies BYTE C[] */
#endif
typedef struct SM9refCipher_st
{
    ULONG EncType;
    BYTE  x[SM9ref_MAX_LEN];
    BYTE  y[SM9ref_MAX_LEN];
    BYTE  h[32];
    ULONG L;
    BYTE  C[];
} SM9Cipher;
#if defined(_MSC_VER)
# pragma warning(pop)
#endif

/* B.1.7 SM9 签名数据结构 (SM9 Signature Structure) */
typedef struct SM9refSignature_st
{
    BYTE h[SM9ref_MAX_LEN];
    BYTE x[SM9ref_MAX_LEN];
    BYTE y[SM9ref_MAX_LEN];
} SM9Signature;

/* B.1.8 SM9 密钥封装数据结构 (SM9 Key Package Structure) */
typedef struct SM9refKeyPackage_st
{
    BYTE x[SM9ref_MAX_LEN];
    BYTE y[SM9ref_MAX_LEN];
} SM9KeyPackage;

/* B.1.9 SM9 用户加密密钥对保护结构 (SM9 User Encrypt Key Pair Protection Structure) */
typedef struct SM9refEncEnvelopedKey_st
{
    ULONG               version;
    ULONG               ulSymmAlgID;
    ULONG               bits;
    BYTE                encryptedPriKey[SM9ref_MAX_LEN * 4];
    SM9EncMasterPublicKey encMastPubKey;
    SM9EncMasterPublicKey tmpMastPubKey;
    ULONG               userIDLen;
    BYTE                userID[256];
    ULONG               keyLen;
    SM9KeyPackage       keyPackage;
} SM9EncEnvelopedKey;

/* B.1.10 SM9 用户签名密钥对保护结构 (SM9 User Sign Key Pair Protection Structure) */
typedef struct SM9refSignEnvelopedKey_st
{
    ULONG                version;
    ULONG                ulSymmAlgID;
    ULONG                bits;
    BYTE                 encryptedPriKey[SM9ref_MAX_LEN * 2];
    SM9SignMasterPublicKey signMastPubKey;
    SM9EncMasterPublicKey  tmpMastPubKey;
    ULONG                userIDLen;
    BYTE                 userID[256];
    ULONG                keyLen;
    SM9KeyPackage        keyPackage;
} SM9SignEnvelopedKey;


#ifdef __cplusplus
}
#endif

#endif /* __SDF_TYPES_H__ */
