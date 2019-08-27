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

#include "calabash.h"
#include "calabash/utils.h"

int sm2_compress_public_key(const char *puk, int puk_len,
                            char *compressed_puk, int *compressed_puk_len)
{
    EC_GROUP *curve_group = NULL;
    EC_POINT *point = NULL;
    BIGNUM *xy = NULL;
    BIGNUM *x;
    BIGNUM *y;
    unsigned char buff[128] = {0x0};
    int result = 0;
    int puk_offset = 0;

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

    if (curve_group == NULL)
    {
        result = -2;
        return result;
    }
    xy = BN_new();
    x = BN_new();
    y = BN_new();

    // create a big number from the unsigned char array
    BN_bin2bn(puk + puk_offset, puk_len, xy);
    BN_bin2bn(puk + puk_offset, 32, x);
    BN_bin2bn(puk + puk_offset + 32, 32, y);

    point = EC_POINT_new(curve_group);
    if (point == NULL)
    {
        result = -3;
        return result;
    }

    if (!EC_POINT_set_affine_coordinates_GFp(curve_group, point, x, y, NULL))
    {
        return -5;
    }

    if (!EC_POINT_is_on_curve(curve_group, point, NULL))
    {
        return -4;
    }

    if ((result = EC_POINT_point2oct(curve_group, point,
                                     POINT_CONVERSION_COMPRESSED,
                                     buff, sizeof(buff), NULL)) != 33)
    {
        return -6;
    }

    memcpy(compressed_puk, buff, result);

    *compressed_puk_len = result;

    return 0;
}

int sm2_uncompress_public_key(const char *in, int in_len, char *out, int *out_len)
{
    EC_GROUP *curve_group = NULL; //
    EC_POINT *point = NULL;
    BIGNUM *x_compressed = NULL;
    int y_chooser_bit = 0;
    int results = 0;
    size_t returnsize = 0;

    unsigned char xy[200] = {0};
    unsigned char x_compressed_byte_array[33] = {0};

    if (in_len != 33) {
        return -1;
    }

    if (in[0] == 0x03) {
	y_chooser_bit = 1;
    } else if (in[0] == 0x02){
	y_chooser_bit = 0;
    } else {
	return -2;
    }

    memcpy(x_compressed_byte_array, in, 33);
    x_compressed = BN_new();

    if (x_compressed == NULL) {
	results = -1;
	goto end;
    }

    curve_group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
    if (curve_group == NULL) {
	results = -2;
	goto end;
    }

    // create a big number from the unsigned char array
    BN_bin2bn(&x_compressed_byte_array[1], sizeof(x_compressed_byte_array) - 1, x_compressed);
    point = EC_POINT_new(curve_group);
    if (point == NULL) {
	results = -3;
	goto end;
    }
    
    //说明：素数域椭圆曲线，给定压缩坐标x和y_bit参数，设置point的几何坐标；用于将Octet-String转化为椭圆曲线上的点；
    EC_POINT_set_compressed_coordinates_GFp(curve_group, point,
					    x_compressed,
					    y_chooser_bit, NULL);

    if (!EC_POINT_is_on_curve(curve_group, point, NULL)) {
	results = -4;
	goto end;
    }
    
    returnsize = EC_POINT_point2oct(curve_group, point,
				    POINT_CONVERSION_UNCOMPRESSED,
				    &xy[0], sizeof(xy), NULL); // 49
    
    if (returnsize != 65) {
	results = -5;
	goto end;
    }

  end:
    BN_free(x_compressed);
    EC_POINT_free(point);
    EC_GROUP_free(curve_group);
    
    if (0 == results) {
        memcpy(out, xy, 65);
        *out_len = 65;
    }
    
    return results;
}

int hex_to_bin(const char *src, int src_len, char *dst, int *dst_len)
{
    char tmpbuff[4] = {0x0};
    int i = 0;
    int t;

    if (src_len < 2 && (src_len % 2) != 0)
    {
        return -1;
    }

    for (i = 0; i < src_len / 2; i++)
    {
        memcpy(tmpbuff, src + i * 2, 2);
        t = strtol(tmpbuff, NULL, 16);
        *(dst + i) = t & 0xff;
        memset(tmpbuff, 0x0, sizeof(tmpbuff));
    }

    if (dst_len != NULL) *dst_len = src_len / 2;
    
    return 0;
}

int bin_to_hex(const char *src, int src_len, char *dst, int *dst_len)
{
    int i = 0;

    for (i = 0; i < src_len; i++)
    {
        sprintf(dst + i * 2, "%02X", *(src + i) & 0xff);
    }

    if (dst_len != NULL) *dst_len = src_len * 2;
    
    return 0;
}

int sm2_sign_with_pem(const unsigned char *pvk, int pvk_len, const char *data, int data_len, char *signature, int *signature_len)
{
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec_key = NULL;

    const EVP_MD *id_md = EVP_sm3();
    const EVP_MD *msg_md = EVP_sm3();

    int type = NID_sm2p256v1;
    unsigned char dgst[EVP_MAX_MD_SIZE];
    size_t dgstlen = 32;
    char *id = "1234567812345678";

    ECDSA_SIG *sm2sig = NULL;
    unsigned char sig[256] = {0x0};
    unsigned int siglen = 0;

    const BIGNUM *sig_r;
    const BIGNUM *sig_s;
    const unsigned char *p;
    int i;
    unsigned char *tp;

    pkey = d2i_AutoPrivateKey(NULL, &pvk, pvk_len);

    ec_key = EVP_PKEY_get0_EC_KEY(pkey);

    const BIGNUM *prv_bn_cont = EC_KEY_get0_private_key(ec_key);

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

int sm2_read_pvk_from_pem_str(const char* pem_str, int pem_str_len, char* pvk, int* pvk_len)
{
    BIO *fp;
    char *name = 0;
    char *header = 0;
    unsigned char *buff = 0x0;
    long buff_len;
    int ret = -1;

    fp = BIO_new_mem_buf(pem_str, pem_str_len);
    if (fp == NULL) return -1;
 
    ret = PEM_read_bio(fp, &name, &header, &buff, &buff_len);
    if (ret && strncmp(name, "EC PARAMETERS", 13) == 0) {
	PEM_read_bio(fp, &name, &header, &buff, &buff_len);

	 EVP_PKEY* pkey = d2i_AutoPrivateKey(NULL, &buff, buff_len);
	 EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pkey);
	 const BIGNUM *prv_bn_cont = EC_KEY_get0_private_key(ec_key);

	 *pvk_len = BN_bn2bin(prv_bn_cont, pvk);
	 ret = 0;
	 
    } else {
	printf("WARNING: This is not a EC key string.\n");
	ret = -3;
	goto err;
    }
  err:
    BIO_free(fp);
    return ret;
}

int sm2_read_puk_from_pemfile(const char* pemfile, char* puk, int* puk_len)
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
        return -2;
    }

    ret = PEM_read_bio(fp, &name, &header, &buff, &buff_len);

    if (strncmp(name, "PUBLIC KEY", 10) == 0) {
	memcpy(puk, buff + (buff_len - 64), 64);
	*puk_len = 64;
	ret = 0;
    } else {
	printf("WARNING: This is not a valid pem key file.\n");
	ret = -3;
    }

    BIO_free(fp);
    return 0;
}

int sm2_read_puk_from_pem_str(const char* pem_str, int pem_str_len, char* puk, int* puk_len)
{
    BIO *fp;
    char *name = 0;
    char *header = 0;
    unsigned char *buff = 0x0;
    long buff_len = 0;
    int ret = -1;

    fp = BIO_new_mem_buf(pem_str, pem_str_len);
    if (fp == NULL) return -1;
    
    ret = PEM_read_bio(fp, &name, &header, &buff, &buff_len);
    
    if (ret && strncmp(name, "PUBLIC KEY", 10) == 0) {
	memcpy(puk, buff + (buff_len - 64), 64);
	*puk_len = 64;
	ret = 0;
    } else {
	printf("WARNING: This is not a valid pem string.\n");
	ret = -3;
    }

    BIO_free(fp);
    return 0;
}


int sm2_get_puk_from_pvk(const char* pvk, int pvk_len, char* puk, int* puk_len)
{
    EC_KEY* ec_key = NULL;
    EC_GROUP* group = NULL;
    EC_POINT* puk_point = NULL;
    BIGNUM* prv_bn = NULL;
    
    int ret = -1;

    prv_bn = BN_bin2bn(pvk, pvk_len, NULL);
    ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    group = EC_KEY_get0_group(ec_key);
    puk_point = EC_POINT_new(group);

    if (!EC_KEY_set_private_key(ec_key, prv_bn))
    {
        printf("set private key failed.\n");
        return -1;
    }

    if (!EC_POINT_mul(group, puk_point, prv_bn, NULL, NULL, NULL))
    {
        return -1;
    }

    ret = EC_POINT_point2oct(group, puk_point,
			     POINT_CONVERSION_UNCOMPRESSED,
			     puk, 256, NULL);
    *puk_len = ret;

    return 0;
}

int sm2_generate_keypair(char* pvk, int* pvk_len, char* puk, int* puk_len)
{
    EC_KEY* ec_key = NULL;
    int ret = -1;
    const BIGNUM* bn_pvk = NULL;
    EC_POINT* puk_point = NULL;
    EC_GROUP *curve_group = NULL;
    
    ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);    

    ret = EC_KEY_generate_key(ec_key);

    if (ret == 0) return -1;

    bn_pvk = EC_KEY_get0_private_key(ec_key);
    *pvk_len = BN_bn2bin(bn_pvk, pvk);

    puk_point = EC_KEY_get0_public_key(ec_key);

    curve_group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);

    ret = EC_POINT_point2oct(curve_group, puk_point,
			     POINT_CONVERSION_UNCOMPRESSED,
			     puk, 256, NULL);

    *puk_len = ret;
    
    return 0;
}

int sm2_encrypt(const char* puk, int puk_len, const char* plain, int plain_len, char* cipher, int* cipher_len)
{

    EC_GROUP* group = NULL;
    EC_KEY* ec_key = NULL;
    BIGNUM* x = NULL;
    BIGNUM* y = NULL;
    int ret = 0;
    int offset = 0;
    int cipher_buffer_len = 0;
    char cipher_buffer[256] = { 0x0 };
    
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

    if (puk_len == 65 && puk[0] == 0x04) {
	offset = 1;
    }
    
    if ((x = BN_bin2bn(puk + offset, 32, NULL)) == NULL)
    {
        ret = -4;
        goto end;
    }
    
    if ((y = BN_bin2bn(puk + 32 + offset, 32, NULL)) == NULL)
    {
        ret = -5;
        goto end;
    }

    if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y))
    {
        ret = -6;
        goto end;
    }

    if(!SM2_encrypt(NID_sm3, plain, plain_len, cipher_buffer, &cipher_buffer_len, ec_key)) {
	return -1;
    }

    ret = decode_cipher_text(cipher_buffer, cipher_buffer_len, cipher, cipher_len);

  end:
    
    return ret;
}

int sm2_decrypt(const char* pvk, int pvk_len, const char* cipher, int cipher_len, char* plain, int* plain_len)
{
    EC_KEY* ec_key = NULL;
    EC_GROUP* group = NULL;
    EC_POINT* puk_point = NULL;
    BIGNUM* prv_bn = NULL;

    char encoded_cipher[512] = { 0x0 };
    int encoded_cipher_len = 0;
    int ret = -1;

    prv_bn = BN_bin2bn(pvk, pvk_len, NULL);
    ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
    group = EC_KEY_get0_group(ec_key);
    puk_point = EC_POINT_new(group);

    if (!EC_KEY_set_private_key(ec_key, prv_bn))
    {
        printf("set private key failed.\n");
        return -1;
    }

    ret = encode_cipher_text(cipher, cipher_len, encoded_cipher, &encoded_cipher_len);
    
    if(!SM2_decrypt(NID_sm3, encoded_cipher, encoded_cipher_len, plain, plain_len, ec_key)) {
	return -2;
    }

    return 0;
}

int sm3_digest(const char* data, int data_len, char* digest)
{
    sm3(data, data_len, digest);
    return 0;
}


int sm4_ecb_encrypt(const char* key, const char* plain, int plain_len, char* cipher)
{
    sms4_key_t sm4_key;
    
    sms4_set_encrypt_key(&sm4_key, key);

    for (int i = 0; i < plain_len / 16; i++) {
	sms4_encrypt(plain + i*16, cipher + i*16, &sm4_key);
    }
    
    return plain_len;
}


int sm4_ecb_decrypt(const char* key, const char* cipher, int cipher_len, char* plain)
{
    sms4_key_t sm4_key;
    
    sms4_set_decrypt_key(&sm4_key, key);

    for (int i = 0; i < cipher_len / 16; i++) {
	sms4_decrypt(cipher + i*16, plain + i*16, &sm4_key);
    }
    
    return cipher_len;
}

int sm4_cbc_encrypt(const char* key, const char* iv, const char* plain, int plain_len, char* cipher)
{
    sms4_key_t sm4_key;
    
    sms4_set_encrypt_key(&sm4_key, key);

    sms4_cbc_encrypt(plain, cipher, plain_len, &sm4_key, iv, 1);

    return plain_len;
}

int sm4_cbc_decrypt(const char* key, const char* iv, const char* cipher, int cipher_len, char* plain)
{
    sms4_key_t sm4_key;
    
    sms4_set_decrypt_key(&sm4_key, key);

    sms4_cbc_encrypt(cipher, plain, cipher_len, &sm4_key, iv, 0);

    return cipher_len;
}
