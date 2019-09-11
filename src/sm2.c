//
// Created by jiangwei on 2017/11/29.
//
#include <string.h>
#include <stdlib.h>

#ifdef WIN32
#include <io.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif // WIN32

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>

#include "calabash/sm2.h"
#include "calabash/utils.h"

#define DEFAULT_ID "1234567812345678"

int cb_sm2_compress_public_key(const char *puk, int puk_len, char *compressed_puk)
{
    EC_GROUP *curve_group = NULL;
    EC_POINT *point = NULL;
    BIGNUM *xy = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    unsigned char buff[128] = {0x0};
    int ret = 0;
    int puk_offset = 0;
    int len = -1;

    if (puk_len != 64 && puk_len != 65) {
        return -1;
    }

    if (puk_len == 65 && puk[0] != 0x4) {
        return -1;
    }

    if (puk_len == 65) {
        puk_offset = 1;
    }

    curve_group = EC_GROUP_new_by_curve_name(NID_sm2);

    if (curve_group == NULL) {
        return -2;
    }

    point = EC_POINT_new(curve_group);
    if (point == NULL) {
        ret = -3;
        goto end;
    }

    if (!EC_POINT_is_on_curve(curve_group, point, NULL)) {
        ret = -4;
        goto end;
    }

    xy = BN_new();
    x = BN_new();
    y = BN_new();

    // create a big number from the unsigned char array
    BN_bin2bn(puk + puk_offset, puk_len, xy);
    BN_bin2bn(puk + puk_offset, 32, x);
    BN_bin2bn(puk + puk_offset + 32, 32, y);

    if (!EC_POINT_set_affine_coordinates_GFp(curve_group, point, x, y, NULL)) {
        ret = -5;
        goto end;
    }

    if ((len = EC_POINT_point2oct(curve_group, point,
                                     POINT_CONVERSION_COMPRESSED,
                                     compressed_puk, CB_SM2_COMPRESS_PUBLICKEY_BYTES, NULL)) != CB_SM2_COMPRESS_PUBLICKEY_BYTES)
    {
        ret = -6;
    } 

end:
    BN_free(xy);
    BN_free(x);
    BN_free(y);
    EC_POINT_free(point);
    EC_GROUP_free(curve_group);

    return ret;
}

int cb_sm2_uncompress_public_key(const char *pk, char *decompressed_puk)
{
    EC_GROUP *curve_group = NULL; //
    EC_POINT *point = NULL;
    BIGNUM *x_compressed = NULL;
    int y_chooser_bit = 0;
    int ret = 0;
    int pk_len = -1;

    unsigned char xy[200] = {0};
    unsigned char x_compressed_byte_array[CB_SM2_COMPRESS_PUBLICKEY_BYTES] = {0};

    if (pk[0] == 0x03) {
	    y_chooser_bit = 1;
    } else if (pk[0] == 0x02){
	    y_chooser_bit = 0;
    } else {
	    return -2;
    }

    memcpy(x_compressed_byte_array, pk, CB_SM2_COMPRESS_PUBLICKEY_BYTES);
    x_compressed = BN_new();

    if (x_compressed == NULL) {
	    ret = -1;
	    goto end;
    }

    curve_group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (curve_group == NULL) {
	    ret = -2;
	    goto end;
    }

    // create a big number from the unsigned char array
    BN_bin2bn(&x_compressed_byte_array[1], sizeof(x_compressed_byte_array) - 1, x_compressed);
    point = EC_POINT_new(curve_group);
    if (point == NULL) {
	    ret = -3;
	    goto end;
    }
    
    //说明：素数域椭圆曲线，给定压缩坐标x和y_bit参数，设置point的几何坐标；用于将Octet-String转化为椭圆曲线上的点；
    EC_POINT_set_compressed_coordinates_GFp(curve_group, point,
					    x_compressed,
					    y_chooser_bit, NULL);

    if (!EC_POINT_is_on_curve(curve_group, point, NULL)) {
	    ret = -4;
	    goto end;
    }
    
    pk_len = EC_POINT_point2oct(curve_group, point,
				    POINT_CONVERSION_UNCOMPRESSED,
				    decompressed_puk, CB_SM2_PUBLICKEY_BYTES, NULL); // 49
    
    if (pk_len != CB_SM2_PUBLICKEY_BYTES) {
        ret = -5;
        goto end;
    }

  end:
    BN_free(x_compressed);
    EC_POINT_free(point);
    EC_GROUP_free(curve_group);
    
    return ret;
}

int cb_sm2_sign(const char *pvk, const char *id, const char *data, int data_len, char *signature)
{
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec_key = NULL;
    EC_GROUP* group = NULL;
    EC_POINT* puk_point = NULL;

    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY_CTX *sctx = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_MD_CTX *cctx = NULL;

    BIGNUM* pvk_bn = NULL;

    size_t siglen = 256;
    unsigned char tmp[128] = { 0x0 };

    pvk_bn = BN_bin2bn(pvk, CB_SM2_SECRETKEY_BYTES, NULL);
    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    group = EC_KEY_get0_group(ec_key);

    if (!EC_KEY_set_private_key(ec_key, pvk_bn))
    {
        cb_debug("set private key failed.\n");
        goto end;
    }
    
    puk_point = EC_POINT_new(group);

    if (!EC_POINT_mul(group, puk_point, pvk_bn, NULL, NULL, NULL))
    {
        goto end;
    }

    EC_KEY_set_public_key(ec_key, puk_point);

    pkey = EVP_PKEY_new();
    if (!EVP_PKEY_set1_EC_KEY(pkey, ec_key)) {
        cb_debug("EVP_PKEY_set1_EC_KEY failed.\n");
        goto end;
    }

    EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);

    mctx = EVP_MD_CTX_new();
    sctx = EVP_PKEY_CTX_new(pkey, NULL);

    if (id == NULL) {
        EVP_PKEY_CTX_set1_id(sctx, (const uint8_t *)DEFAULT_ID, strlen(DEFAULT_ID));
    } else {
        EVP_PKEY_CTX_set1_id(sctx, (const uint8_t *)id, strlen(id));
    }

    EVP_MD_CTX_set_pkey_ctx(mctx, sctx);

    EVP_DigestSignInit(mctx, NULL, EVP_sm3(), NULL, pkey);
    EVP_DigestSignUpdate(mctx, data, data_len);
    EVP_DigestSignFinal(mctx, tmp, &siglen);

    siglen = cb_ut_decode_ec_sign_str(tmp, siglen, signature);

end:
    EC_KEY_free(ec_key);
    EC_POINT_free(puk_point);
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_CTX_free(sctx);
    EVP_PKEY_free(pkey);

    return siglen;
}

int cb_sm2_sign_verify(const unsigned char *puk, const char *id, const unsigned char *data, int data_len, const unsigned char *signature)
{
    int ret = -1;
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec_key = NULL;
    EC_GROUP *group = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    EVP_PKEY_CTX *mctx = NULL;
    EVP_PKEY_CTX *sctx = NULL;

    int puk_offset = 1;
    size_t siglen = 256;
    unsigned char tmp[128] = { 0x0 };

    unsigned long ulErr;
    char szErrMsg[1024] = { 0x0 };
    char *pTmp = NULL;

    group = EC_GROUP_new_by_curve_name(NID_sm2);

    if (!(ec_key = EC_KEY_new())) {
        ret = -2;
        goto end;
    }

    if (!EC_KEY_set_group(ec_key, group)) {
        ret = -3;
        goto end;
    }

    if ((x = BN_bin2bn(puk + puk_offset, 32, NULL)) == NULL) {
        ret = -4;
        goto end;
    }

    if ((y = BN_bin2bn(puk + puk_offset + 32, 32, NULL)) == NULL) {
        ret = -5;
        goto end;
    }

    if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) {
        ret = -6;
        goto end;
    }

    pkey = EVP_PKEY_new();
    if (!EVP_PKEY_set1_EC_KEY(pkey, ec_key)) {
        cb_debug("EVP_PKEY_set1_EC_KEY failed.\n");
        goto end;
    }

    EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);

    mctx = EVP_MD_CTX_new();
    sctx = EVP_PKEY_CTX_new(pkey, NULL);

    if (id == NULL) {
        EVP_PKEY_CTX_set1_id(sctx, (const uint8_t *)DEFAULT_ID, strlen(DEFAULT_ID));
    } else {
        EVP_PKEY_CTX_set1_id(sctx, (const uint8_t *)id, strlen(id));
    }

    EVP_MD_CTX_set_pkey_ctx(mctx, sctx);

    siglen = cb_ut_encode_ec_sign_str(signature, 64, tmp);
    
    if (!EVP_DigestVerifyInit(mctx, NULL, EVP_sm3(), NULL, pkey)) {
        cb_debug("EVP_DigestVerifyInit is failed");
    }
    if (!EVP_DigestVerifyUpdate(mctx, data, data_len)) {
        cb_debug("EVP_DigestVerifyUpdate is failed");
    }

    ret = EVP_DigestVerifyFinal(mctx, tmp, siglen);
    cb_debug("cb siglen=%d ret=%d", siglen, ret);
    if (ret != 1) {
        ulErr = ERR_get_error();
        pTmp = ERR_error_string(ulErr,szErrMsg); 

        cb_debug("pctx is:%s", szErrMsg);
        goto end;
    }
    ret = 0;
end:
return ret;

}

int cb_sm2_keypair(char* pk, char* sk)
{
    EC_KEY* ec_key = NULL;
    int ret = 0;
    BIGNUM* bn_pvk = NULL;
    EC_POINT* puk_point = NULL;
    EC_GROUP *curve_group = NULL;
    
    ec_key = EC_KEY_new_by_curve_name(NID_sm2);    
    int ec_ret = EC_KEY_generate_key(ec_key);

    if (ec_ret == 0) {
        ret = -1;
        goto end;
    }

    bn_pvk = EC_KEY_get0_private_key(ec_key);
    BN_bn2bin(bn_pvk, sk);
    

    puk_point = EC_KEY_get0_public_key(ec_key);
    curve_group = EC_GROUP_new_by_curve_name(NID_sm2);

    ec_ret = EC_POINT_point2oct(curve_group, puk_point,
			     POINT_CONVERSION_UNCOMPRESSED,
			     pk, CB_SM2_PUBLICKEY_BYTES, NULL);
    
    if (ec_ret != CB_SM2_PUBLICKEY_BYTES) ret = -2;

end:
    EC_GROUP_free(curve_group);
    EC_KEY_free(ec_key);

    return ret;
}

int cb_sm2_encrypt(const char* pk, const char* plain, int plain_len, char* cipher)
{
    EC_GROUP* group = NULL;
    EC_KEY* ec_key = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *cctx = NULL;
    //int ctext_len = 256;
    size_t ctext_len = 256;

    char ciphertext[256] = { 0x0 };
    unsigned long ulErr;
    char szErrMsg[1024] = { 0x0 };
    char *pTmp = NULL;
    BIO *bio = NULL;
    int ec_ret = -1;
    int ret = 0;
    int publickey_offset = 0;
    
    BIGNUM* x = NULL;
    BIGNUM* y = NULL;
    char tmp_buff[256] = { 0x0 };
    
    group = EC_GROUP_new_by_curve_name(NID_sm2);
    ec_key = EC_KEY_new();
    
    if (group == NULL) {
        ulErr = ERR_get_error();
        pTmp = ERR_error_string(ulErr,szErrMsg); 
        cb_debug("pctx szErrMsg is:%s", szErrMsg);
        return -1;
    }

    if ((pk[0]&0xFF) == 0x4) publickey_offset = 1;
    cb_debug("pk[0]=%02X offset=%d", pk[0]&0xFF, publickey_offset);

    EC_KEY_set_group(ec_key, group);
    if ((x = BN_bin2bn(pk + publickey_offset, 32, NULL)) == NULL) {
        ret = -4;
        goto end;
    }
    
    if ((y = BN_bin2bn(pk + publickey_offset + 32, 32, NULL)) == NULL) {
        ret = -5;
        cb_debug("-5");
        goto end;
    }

    if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) {
        cb_debug("-6");
        ret = -6;
        goto end;
    }

    pkey = EVP_PKEY_new();

    EVP_PKEY_set1_EC_KEY(pkey, ec_key);
    
    EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);
    

        // step 3
    cctx = EVP_PKEY_CTX_new(pkey, NULL);
    // if (cctx == NULL) {
    //     ulErr = ERR_get_error();
    //     pTmp = ERR_error_string(ulErr,szErrMsg); 

    //     cb_debug("pctx is:%s", szErrMsg);
    // }
    cb_debug("plain lenis:%d", plain_len);
    EVP_PKEY_encrypt_init(cctx);

    EVP_PKEY_encrypt(cctx, tmp_buff, &ctext_len, plain, plain_len);
    
    ctext_len = cb_ut_decode_ec_cipher_str(tmp_buff, ctext_len, cipher);
    ret = ctext_len;
end:
    EVP_PKEY_CTX_free(cctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);

    return ret;
}

int cb_sm2_decrypt(const char* sk, const char* cipher, int cipher_len, char* plain)
{
    EVP_PKEY *pkey = NULL;
    EC_KEY* ec_key = NULL;
    EC_GROUP* group = NULL;
    EC_POINT* puk_point = NULL;
    BIGNUM* pvk_bn = NULL;
    EVP_PKEY_CTX *cctx = NULL;

    int ret = -1;
    size_t plain_len = 0;
    char tmp_buff[512] = { 0x0 };
    
    pvk_bn = BN_bin2bn(sk, CB_SM2_SECRETKEY_BYTES, NULL);
    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    group = EC_KEY_get0_group(ec_key);
    puk_point = EC_POINT_new(group);

    if (!EC_KEY_set_private_key(ec_key, pvk_bn))
    {
        cb_debug("Set private key failed.\n");
        ret = -1;
        goto end;
    }

    pkey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(pkey, ec_key);
    EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);

    cctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_decrypt_init(cctx);

    int tmp_len = cb_ut_encode_ec_cipher_str(cipher, cipher_len, tmp_buff);
    
    EVP_PKEY_decrypt(cctx, plain, &plain_len, tmp_buff, tmp_len);
    ret = plain_len;
    
end:
    EC_KEY_free(ec_key);
    EC_POINT_free(puk_point);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(cctx);

    cb_debug("plain len=%d", ret);
    
    return ret;
}

int cb_sm3_digest(const char* data, int data_len, char* digest)
{
    EVP_Digest(data, data_len, digest, NULL, EVP_sm3(), NULL);
    return CB_SM3_DIGEST_BYTES;
}

static inline void *kdf_sm3(const char* in, int in_len, char* out, int *out_len)
{
    char tmp_out[CB_SM3_DIGEST_BYTES] = { 0x0 };

    // sm3(in, in_len, tmp_out);
    EVP_Digest(in, in_len, tmp_out, NULL, EVP_sm3(), NULL);

    memcpy(out, tmp_out, CB_SM2_DERIVATEKEY_BYTES);
    *out_len = CB_SM2_DERIVATEKEY_BYTES;
}

int cb_sm2_compute_key(const char* private_key, const char* public_key, char* key)
{
    char buf[32] = { 0x0 };

    EC_KEY* ec_key = NULL;
    EC_GROUP* group = NULL;
    EC_POINT* puk_point = NULL;
    BIGNUM* prv_bn = NULL;

    char encoded_cipher[512] = { 0x0 };
    int encoded_cipher_len = 0;
    int ret = -1;

    prv_bn = BN_bin2bn(private_key, 32, NULL);
    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    group = EC_KEY_get0_group(ec_key);
    puk_point = EC_POINT_new(group);

    if (!EC_KEY_set_private_key(ec_key, prv_bn))
    {
        printf("set private key failed.\n");
        return -1;
    }

    EC_POINT_oct2point(group, puk_point, public_key, CB_SM2_PUBLICKEY_BYTES, NULL);

    ret = ECDH_compute_key(key, CB_SM2_DERIVATEKEY_BYTES, puk_point,ec_key, kdf_sm3);

end:
    EC_KEY_free(ec_key);
    EC_POINT_free(puk_point);

    return ret;
}

int cb_sm2_get_puk_from_pvk(const char* pvk, char* puk)
{
    EC_KEY* ec_key = NULL;
    EC_GROUP* group = NULL;
    EC_POINT* puk_point = NULL;
    BIGNUM* prv_bn = NULL;
    
    int ret = -1;
    int len = -1;

    prv_bn = BN_bin2bn(pvk, CB_SM2_SECRETKEY_BYTES, NULL);
    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    group = EC_KEY_get0_group(ec_key);
    puk_point = EC_POINT_new(group);

    if (!EC_KEY_set_private_key(ec_key, prv_bn))
    {
        printf("set private key failed.\n");
        ret -1;
        goto end;
    }

    if (!EC_POINT_mul(group, puk_point, prv_bn, NULL, NULL, NULL))
    {
        ret = -2;
        goto end;
    }

    len = EC_POINT_point2oct(group, puk_point,
			     POINT_CONVERSION_UNCOMPRESSED,
			     puk, CB_SM2_PUBLICKEY_BYTES, NULL);

    if (len != CB_SM2_PUBLICKEY_BYTES) ret = -3;

end:
    EC_KEY_free(ec_key);
    EC_POINT_free(puk_point);
    BN_free(prv_bn);

    return 0;
}
