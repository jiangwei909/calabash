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

#include "calabash.h"

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

    do
    {
        if (in[0] == 0x03)
        {
            y_chooser_bit = 1;
        }
        else
        {
            y_chooser_bit = 0;
        }

        memcpy(x_compressed_byte_array, in, 33);
        x_compressed = BN_new();

        if (x_compressed == NULL)
        {
            results = -1;
            break;
        }
        curve_group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
        if (curve_group == NULL)
        {
            results = -2;
            break;
        }

        // create a big number from the unsigned char array
        BN_bin2bn(&x_compressed_byte_array[1], sizeof(x_compressed_byte_array) - 1, x_compressed);
        point = EC_POINT_new(curve_group);
        if (point == NULL)
        {
            results = -3;
            break;
        }
        //说明：素数域椭圆曲线，给定压缩坐标x和y_bit参数，设置point的几何坐标；用于将Octet-String转化为椭圆曲线上的点；
        EC_POINT_set_compressed_coordinates_GFp(curve_group, point,
                                                x_compressed,
                                                y_chooser_bit, NULL);

        //printf("results=%d\r\n",results);
        if (!EC_POINT_is_on_curve(curve_group, point, NULL))
        {
            results = -4;
            break;
        }

        returnsize = EC_POINT_point2oct(curve_group, point,
                                        POINT_CONVERSION_UNCOMPRESSED,
                                        &xy[0], sizeof(xy), NULL); // 49

        if (returnsize != 65)
        {
            results = -5;
            break;
        }
        //printf("returnsize=%d\r\n",returnsize);
    } while (0);

    // clean up allocated memory
    if (x_compressed)
        BN_free(x_compressed);
    if (point)
        EC_POINT_free(point);
    if (curve_group)
        EC_GROUP_free(curve_group);

    if (0 == results)
    {
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

    *dst_len = src_len / 2;

    for (i = 0; i < *dst_len; i++)
    {
        memcpy(tmpbuff, src + i * 2, 2);
        t = strtol(tmpbuff, NULL, 16);
        *(dst + i) = t & 0xff;
        memset(tmpbuff, 0x0, sizeof(tmpbuff));
    }

    return 0;
}

int bin_to_hex(const char *src, int src_len, char *dst, int *dst_len)
{
    int i = 0;

    for (i = 0; i < src_len; i++)
    {
        sprintf(dst + i * 2, "%02X", *(src + i) & 0xff);
    }

    *dst_len = src_len * 2;

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
    EC_GROUP *group;

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

#ifdef DEBUG
    printf("puk[%d] = ", puk_len);
    for (i = 0; i < puk_len; i++)
    {
        printf("%02X", puk[i] & 0xff);
    }
    printf("\n");

    printf("data[%d] = ", data_len);
    for (i = 0; i < data_len; i++)
    {
        printf("%02X", data[i] & 0xff);
    }
    printf("\n");

    printf("sign[%d] = ", sig_len);
    for (i = 0; i < sig_len; i++)
    {
        printf("%02X", signature[i] & 0xff);
    }
    printf("\n");
#endif

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

    if ((x = BN_bin2bn(puk, 32, NULL)) == NULL)
    {
        ret = -4;
        goto end;
    }
    if ((y = BN_bin2bn(puk + 32, 32, NULL)) == NULL)
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
#ifdef DEBUG
    printf("ret = [%d] = ", ret);
    ret = EVP_MD_size(msg_md);
    printf("EVP_MD_size = [%d] = ", ret);

    printf("dgst[%d] = ", dgstlen);
    for (i = 0; i < dgstlen; i++)
    {
        printf("%02X", dgst[i] & 0xff);
    }
    printf("\n");

    printf("id_md [%d] = ", 64);
    for (i = 0; i < 64; i++)
    {
        printf("%02X", ((unsigned char *)id_md)[i] & 0xff);
    }
    printf("\n");

    printf("msg_md[%d] = ", 64);
    for (i = 0; i < 64; i++)
    {
        printf("%02X", ((unsigned char *)msg_md)[i] & 0xff);
    }
    printf("\n");

    printf("ec_key[%d] = ", 64);
    for (i = 0; i < 64; i++)
    {
        printf("%02X", ((unsigned char *)ec_key)[i] & 0xff);
    }
    printf("\n");
#endif

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
#ifdef DEBUG
    printf("sig = ");
    for (i = 0; i < pp_len; i++)
    {
        printf("%02X", pp_sig[i]);
    }
    printf("\n");
#endif
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

    if (puk_len == 65) offset = 1;
    
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

    ret = remove_format_from_cipher_text(cipher_buffer, cipher_buffer_len, cipher, cipher_len);

  end:
    
    return ret;
}

int remove_format_from_cipher_text(const unsigned char* cipher_text, int cipher_text_len,
				   unsigned char* no_fmt_string, int* no_fmt_string_len)
{
    int char_of_length = 0;
    int length_of_content = 0;
    int offset = 0;
    
    if (cipher_text[0] != 0x30 ) return -1;

    if (cipher_text[1] > 0x80) {
	char_of_length = cipher_text[1] - 0x80;
	switch(char_of_length) {
	case 1:
	    length_of_content = cipher_text[2];
	    offset = 3;
	    break;
	case 2:
	    length_of_content = cipher_text[2]*256 + cipher_text[3];
	    offset = 4;
	    break;
	case 3:
	    length_of_content = cipher_text[2]*256*256 + cipher_text[3]*256 + cipher_text[4];
	    offset = 5;
	    break;
	}
		
    } else {
	length_of_content = cipher_text[1];
	offset = 2;
    }

    if (length_of_content + offset != cipher_text_len) return -2;

    offset += 1;
    *no_fmt_string_len = 0;
    for (int i = 0; i < 4; i++) {
	
	int length_of_c1x = *(cipher_text+offset);
	offset +=1;
	if (i < 3) {
	    if (length_of_c1x > 32) {
		offset += 1;
	    }
	    length_of_c1x = 32;
	}

	memcpy(no_fmt_string + i*32, cipher_text + offset, length_of_c1x);
	offset += length_of_c1x;
	*no_fmt_string_len += length_of_c1x;

	offset += 1;
    }
    
    return 0;
}
