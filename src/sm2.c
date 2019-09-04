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
#include <openssl/gmapi.h>
#include <openssl/sms4.h>

#include "calabash/sm2.h"
#include "calabash/utils.h"

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

    curve_group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);

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

    curve_group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
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

int sm2_sign(const char *pvk, int pvk_len, const char *data, int data_len, char *signature, int *signature_len)
{
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec_key = NULL;
    EC_GROUP *group = NULL;

    const EVP_MD *id_md = EVP_sm3();
    const EVP_MD *msg_md = EVP_sm3();

    int type = NID_sm2p256v1;
    unsigned char dgst[EVP_MAX_MD_SIZE];
    size_t dgstlen = 32;
    char *id = "1234567812345678";

    ECDSA_SIG *sm2sig = NULL;
    unsigned char sig[256] = {0x0};
    unsigned int siglen = 0;

    EC_POINT *pub_key = NULL;

    BIGNUM *prv_bn = NULL;
    const BIGNUM *sig_r;
    const BIGNUM *sig_s;
    const unsigned char *p;
    int i;
    unsigned char *tp;

    prv_bn = BN_bin2bn(pvk, pvk_len, NULL);
    ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);

    group = EC_KEY_get0_group(ec_key);
    pub_key = EC_POINT_new(group);

    if (!EC_KEY_set_private_key(ec_key, prv_bn))
    {
        printf("set private key failed.\n");
        return -1;
    }

    if (!EC_POINT_mul(group, pub_key, prv_bn, NULL, NULL, NULL))
    {
        printf("compute public key failed.\n");
        return -1;
    }

    if (!EC_KEY_set_public_key(ec_key, pub_key))
    {
        printf("set public key failed.\n");
        return -1;
    }

    SM2_compute_message_digest(id_md, msg_md,
                               (const unsigned char *)data, data_len, id, strlen(id),
                               dgst, &dgstlen, ec_key);

#ifdef DEBUG
    printf("dgst1 = ");
    for (i = 0; i < dgstlen; i++)
    {
        printf("%02X", dgst[i]);
    }
    printf("\n");
#endif

    siglen = sizeof(sig);
    if (!SM2_sign(type, dgst, dgstlen, sig, &siglen, ec_key))
    {
        fprintf(stderr, "error: %s %d\n", __FUNCTION__, __LINE__);
        return -1;
    }

    p = sig;
    sm2sig = d2i_ECDSA_SIG(NULL, &p, siglen);

    ECDSA_SIG_get0(sm2sig, &sig_r, &sig_s);

    siglen = BN_bn2bin(sig_r, signature);
    *signature_len = siglen;

    siglen = BN_bn2bin(sig_s, signature + siglen);

    *signature_len += siglen;

    return 0;
}

int sm2_sign_verify(const unsigned char *puk, int puk_len, const unsigned char *data, int data_len, const unsigned char *signature, int sig_len)
{
    EC_KEY *ec_key = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    EC_GROUP *group;
    int ret = -1;
    const EVP_MD *id_md = EVP_sm3();
    const EVP_MD *msg_md = EVP_sm3();

    int type = NID_sm2p256v1;
    unsigned char dgst[EVP_MAX_MD_SIZE];
    size_t dgstlen = 32;
    char *id = "1234567812345678";
    int i = 0;
    ECDSA_SIG *sig = NULL;
    BIGNUM *r = NULL;
    BIGNUM *s = NULL;
    unsigned char *pp = NULL;
    unsigned char *pp_sig = NULL;
    int pp_len = 0;
    unsigned char *tp = NULL;
    int puk_offset = 0;

    if (puk_len == 65 && puk[0] == 0x04) {
	puk_offset = 1;
    }
    
    group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);

    if (!(ec_key = EC_KEY_new()))
    {
        ret = -2;
        goto end;
    }

    if (!EC_KEY_set_group(ec_key, group))
    {
        ret = -3;
        goto end;
    }

    if ((x = BN_bin2bn(puk + puk_offset, 32, NULL)) == NULL)
    {
        ret = -4;
        goto end;
    }
    if ((y = BN_bin2bn(puk + puk_offset + 32, 32, NULL)) == NULL)
    {
        ret = -5;
        goto end;
    }

    if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y))
    {
        ret = -6;
        goto end;
    }

    ret = SM2_compute_message_digest(id_md, msg_md,
                                     data, data_len, id, strlen(id),
                                     dgst, &dgstlen, ec_key);

    if ((r = BN_bin2bn(signature, 32, NULL)) == NULL)
    {
        ret = -4;
        goto end;
    }

    if ((s = BN_bin2bn(signature + 32, 32, NULL)) == NULL)
    {
        ret = -5;
        goto end;
    }

    pp_len = ECDSA_size(ec_key);
    if ((pp_sig = OPENSSL_malloc(pp_len)) == NULL)
    {
        fprintf(stderr, "error : %s %d\n", __FUNCTION__, __LINE__);
        goto end;
    }

    sig = ECDSA_SIG_new();

    if (!ECDSA_SIG_set0(sig, r, s))
    {
        fprintf(stderr, "error : %s %d\n", __FUNCTION__, __LINE__);
        goto end;
    }

    pp = pp_sig;

    pp_len = i2d_ECDSA_SIG(sig, &pp);
    
    ret = SM2_verify(type, dgst, dgstlen, pp_sig, pp_len, ec_key);

    if (1 != ret)
    {
        fprintf(stderr, "error %d : %s %d\n", ret, __FUNCTION__, __LINE__);
        ret = -7;
        goto end;
    }

    ret = 0;

end:

    return ret;
}

int sm2_read_pvk_from_pemfile(const char* pemfile, char* pvk, int* pvk_len)
{
    BIO *fp;
    char *name = 0;
    char *header = 0;
    unsigned char *buff = 0x0;
    long buff_len;
    int ret = -1;

#ifdef WIN32
    ret = _access(pemfile, 0);
#else
    ret = access(pemfile, R_OK);
#endif
    
    if (ret != 0){
        printf("Not found file: %s\n", pemfile);
        return -1;
    }

    fp = BIO_new_file(pemfile, "r");
    if (fp == NULL){
        printf("Failed to open file: %s", pemfile);
        ret = -2;
        goto err;
    }

    ret = PEM_read_bio(fp, &name, &header, &buff, &buff_len);
    if (strncmp(name, "EC PARAMETERS", 13) == 0) {
	PEM_read_bio(fp, &name, &header, &buff, &buff_len);

	 EVP_PKEY* pkey = d2i_AutoPrivateKey(NULL, &buff, buff_len);
	 EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pkey);
	 const BIGNUM *prv_bn_cont = EC_KEY_get0_private_key(ec_key);

	 *pvk_len = BN_bn2bin(prv_bn_cont, pvk);
	 ret = 0;
	 
    } else {
	printf("WARNING: This is not a EC key file.\n");
	ret = -3;
	goto err;
    }
  err:
    BIO_free(fp);
    return ret;
}

int cb_sm2_keypair(char* pk, char* sk)
{
    EC_KEY* ec_key = NULL;
    int ret = 0;
    BIGNUM* bn_pvk = NULL;
    EC_POINT* puk_point = NULL;
    EC_GROUP *curve_group = NULL;
    
    ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);    
    int ec_ret = EC_KEY_generate_key(ec_key);

    if (ec_ret == 0) {
        ret = -1;
        goto end;
    }

    bn_pvk = EC_KEY_get0_private_key(ec_key);
    BN_bn2bin(bn_pvk, sk);
    

    puk_point = EC_KEY_get0_public_key(ec_key);
    curve_group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);

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
    BIGNUM* x = NULL;
    BIGNUM* y = NULL;
    int ret = 0;
    int offset = 1;
    int cipher_buffer_len = 0;
    char cipher_buffer[256] = { 0x0 };
    int cipher_len = 0;
    
    group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);

    if (!(ec_key = EC_KEY_new())) {
        ret = -2;
        goto end;
    }

    if (!EC_KEY_set_group(ec_key, group)) {
        ret = -3;
        goto end;
    }
    
    if ((x = BN_bin2bn(pk + offset, 32, NULL)) == NULL) {
        ret = -4;
        goto end;
    }
    
    if ((y = BN_bin2bn(pk + 32 + offset, 32, NULL)) == NULL) {
        ret = -5;
        goto end;
    }

    if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) {
        ret = -6;
        goto end;
    }

    if(!SM2_encrypt(NID_sm3, plain, plain_len, cipher_buffer, &cipher_buffer_len, ec_key)) {
	    return -1;
    }

    ret = decode_cipher_text(cipher_buffer, cipher_buffer_len, cipher, &cipher_len);
    ret = cipher_len;

  end:
    
    return ret;
}

int cb_sm2_decrypt(const char* sk, const char* cipher, int cipher_len, char* plain)
{
    EC_KEY* ec_key = NULL;
    EC_GROUP* group = NULL;
    EC_POINT* puk_point = NULL;
    BIGNUM* prv_bn = NULL;

    char encoded_cipher[512] = { 0x0 };
    int encoded_cipher_len = 0;
    int ret = -1;
    int plain_len = -1;

    prv_bn = BN_bin2bn(sk, CB_SM2_SECRETKEY_BYTES, NULL);
    ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    group = EC_KEY_get0_group(ec_key);
    puk_point = EC_POINT_new(group);

    if (!EC_KEY_set_private_key(ec_key, prv_bn))
    {
        printf("set private key failed.\n");
        return -1;
    }

    ret = encode_cipher_text(cipher, cipher_len, encoded_cipher, &encoded_cipher_len);
    
    if(!SM2_decrypt(NID_sm3, encoded_cipher, encoded_cipher_len, plain, &plain_len, ec_key)) {
	    return -2;
    }

    return plain_len;
}

int cb_sm3_digest(const char* data, int data_len, char* digest)
{
    sm3(data, data_len, digest);
    return CB_SM3_DIGEST_BYTES;
}

static inline void *kdf_sm3(const char* in, int in_len, char* out, int *out_len)
{
    sm3(in, in_len, out);
    *out_len = CB_SM3_DIGEST_BYTES;
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
    ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    group = EC_KEY_get0_group(ec_key);
    puk_point = EC_POINT_new(group);

    if (!EC_KEY_set_private_key(ec_key, prv_bn))
    {
        printf("set private key failed.\n");
        return -1;
    }

    EC_POINT_oct2point(group, puk_point, public_key, 65, NULL);

    ret = ECDH_compute_key(key, 32, puk_point,ec_key, kdf_sm3);

    return ret;
}


int cb_sm2_compute_puk(const char* pvk, char* puk)
{
    EC_KEY* ec_key = NULL;
    EC_GROUP* group = NULL;
    EC_POINT* puk_point = NULL;
    BIGNUM* prv_bn = NULL;
    
    int ret = -1;
    int len = -1;

    prv_bn = BN_bin2bn(pvk, CB_SM2_SECRETKEY_BYTES, NULL);
    ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
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