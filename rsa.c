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
#include "internal.h"

int rsa_read_key_from_pem_file(const char* pemfile, char* puk)
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

    if (ret > 0) {
	memcpy(puk, buff, buff_len);
	ret = buff_len;
    } else {
	printf("WARNING: This is not a valid pem file.\n");
	ret = -3;
    }


    BIO_free(fp);
    return ret;
}

int rsa_read_key_from_pem_str(const char* pem_str, int pem_str_len, char* puk)
{
    BIO *fp;
    char *name = 0;
    char *header = 0;
    unsigned char *buff = 0x0;
    long buff_len;
    int ret = -1;
    
    fp = BIO_new_mem_buf(pem_str, pem_str_len);

    ret = PEM_read_bio(fp, &name, &header, &buff, &buff_len);

    if (ret > 0) {
	memcpy(puk, buff, buff_len);
	ret = buff_len;
    } else {
	printf("WARNING: This is not a valid pem string.\n");
	ret = -3;
    }

    BIO_free(fp);
    return ret;
}

int rsa_encrypt(const char* puk, int puk_len, const char* plain, int plain_len, char* cipher)
{
    const unsigned char **u_puk = (const unsigned char**)&puk;

    EVP_PKEY* pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, u_puk, puk_len);

    if (pkey == NULL) return -1;
    
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    
    int ret = RSA_public_encrypt(plain_len, plain, cipher, rsa, RSA_PKCS1_PADDING);    
    RSA_free(rsa);
    
    return ret;
}

int rsa_decrypt(const char* pvk, int pvk_len, const char* cipher, int cipher_len, char* plain)
{
    EVP_PKEY* pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &pvk, pvk_len);

    if (pkey == NULL) return -1;
    
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    
    int ret = RSA_private_decrypt(cipher_len, cipher, plain, rsa, RSA_PKCS1_PADDING);    
    RSA_free(rsa);
    
    return ret;
}

int rsa_sign(const char* pvk, int pvk_len, const char* msg, int msg_len, char* sign)
{
    int digest_alg = -1;
    int sign_len = 0;
    
    EVP_PKEY* pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &pvk, pvk_len);

    if (pkey == NULL) return -1;
    
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);

    switch(msg_len) {
    case 16:
	digest_alg = NID_md5;
	break;
    case 20:
	digest_alg = NID_sha1;
	break;
    case 28:
	digest_alg = NID_sha224;
	break;
    case 32:
	digest_alg = NID_sha256;
	break;
    case 48:
	digest_alg = NID_sha384;
	break;
    case 64:
	digest_alg = NID_sha512;
	break;
    default:
	return -2;
    }
    
    int ret = RSA_sign(digest_alg, msg, msg_len, sign, &sign_len, rsa);
    
    RSA_free(rsa);

    if (ret > 0) return sign_len;

    ret = -3;
    
    return ret;
}

int rsa_verify(const char* puk, int puk_len, const char* msg, int msg_len, const char* sign, int sign_len)
{
    int digest_alg = -1;
    
    EVP_PKEY* pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, &puk, puk_len);

    if (pkey == NULL) return -1;
    
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);

    switch(msg_len) {
    case 16:
	digest_alg = NID_md5;
	break;
    case 20:
	digest_alg = NID_sha1;
	break;
    case 28:
	digest_alg = NID_sha224;
	break;
    case 32:
	digest_alg = NID_sha256;
	break;
    case 48:
	digest_alg = NID_sha384;
	break;
    case 64:
	digest_alg = NID_sha512;
	break;
    default:
	return -2;
    }
    
    int ret = RSA_verify(digest_alg, msg, msg_len, sign, sign_len, rsa);
    
    RSA_free(rsa);

    if (ret > 0) return 0;

    ret = -3;
    
    return ret;
}

int rsa_generate_key(int bits, char* pvk, int* pvk_len, char* puk, int * puk_len)
{
    int ret = -1;
    RSA *rsa = RSA_new();

    BIGNUM *e = BN_new();
    BN_set_word(e, 65537);
    
    if (bits % 8 !=0 ) return -1;

    if (pvk == NULL || puk == NULL) return -2;

    ret = RSA_generate_key_ex(rsa, bits, e, NULL);

    /* To get the C-string PEM form: */
    BIO *bio = BIO_new(BIO_s_mem());
    BIO *bio2 = BIO_new(BIO_s_mem());
    
    PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);

    *pvk_len = BIO_pending(bio);

    char *name = 0;
    char *header = 0;
    unsigned char *buff = 0x0;
    long buff_len;
    
    ret = PEM_read_bio(bio, &name, &header, &buff, &buff_len);

    if (ret > 0) {
	memcpy(pvk, buff, buff_len);
	*pvk_len = buff_len;
    } else {
	ret = -3;
    }

    BIO_free_all(bio);
    
    //BIO_read(bio, pvk, *pvk_len);

    PEM_write_bio_RSAPublicKey(bio2, rsa);

    *puk_len = BIO_pending(bio2);
    //BIO_read(bio, puk, *puk_len);

    ret = PEM_read_bio(bio2, &name, &header, &buff, &buff_len);
    if (ret > 0) {
	memcpy(puk, buff, buff_len);
	*puk_len = buff_len;
    } else {
	ret = -3;
    }
    
    BIO_free_all(bio2);
    
    RSA_free(rsa);
    
    return 0;
}

int rsa_dump_puk_to_pem_str(const char* puk, int puk_len, char* str)
{
    int str_len;
    int ret = -1;
    
    EVP_PKEY* pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, &puk, puk_len);

    if (pkey == NULL) return -1;
    
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);

    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio, rsa);

    str_len = BIO_pending(bio);
    BIO_read(bio, str, str_len);
    ret = str_len;
    
    BIO_free_all(bio);
    
    return ret;
}

int rsa_dump_puk_to_pkcs8_pem_str(const char* puk, int puk_len, char* str)
{
    int str_len;
    int ret = -1;
    
    EVP_PKEY* pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, &puk, puk_len);

    if (pkey == NULL) return -1;
    
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);

    str_len = BIO_pending(bio);
    BIO_read(bio, str, str_len);
    ret = str_len;
    
    BIO_free_all(bio);
    
    return ret;
}

int rsa_dump_pvk_to_pem_str(const char* pvk, int pvk_len, char* str)
{
    int ret = -1;
    
    EVP_PKEY* pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &pvk, pvk_len);

    if (pkey == NULL) return -1;
    
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);

    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);
    
    
    ret = BIO_pending(bio);
    
    BIO_read(bio, str, ret);
    
    BIO_free_all(bio);
    
    return ret;
}

int rsa_dump_pvk_to_pkcs8_pem_str(const char* pvk, int pvk_len, const char* password, char* str)
{
    int ret = -1;
    
    EVP_PKEY* pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &pvk, pvk_len);

    if (pkey == NULL) return -1;
    
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PKCS8PrivateKey(bio, pkey, NULL, NULL, 0, password, NULL);
    
    ret = BIO_pending(bio);
    
    BIO_read(bio, str, ret);
    
    BIO_free_all(bio);
    
    return ret;
}


int rsa_dump_puk_to_pem_file(const char* puk, int puk_len, char* file_name)
{
    int str_len;
    int ret = -1;
    
    EVP_PKEY* pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, &puk, puk_len);

    if (pkey == NULL) return -1;
    
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);

    BIO *bio = BIO_new_file(file_name, "w");
    if (bio == NULL) return -2;
    
    ret = PEM_write_bio_RSAPublicKey(bio, rsa);
    
    BIO_free_all(bio);
    
    return ret;
}

int rsa_dump_puk_to_pkcs8_pem_file(const char* puk, int puk_len, char* file_name)
{
    int str_len;
    int ret = -1;
    
    EVP_PKEY* pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, &puk, puk_len);

    if (pkey == NULL) return -1;

    BIO *bio = BIO_new_file(file_name, "w");
    if (bio == NULL) return -2;
    
    ret = PEM_write_bio_PUBKEY(bio, pkey);
    
    BIO_free_all(bio);
    
    return ret;
}

int rsa_dump_pvk_to_pem_file(const char* pvk, int pvk_len, char* file_name)
{
    
    int ret = -1;
    
    EVP_PKEY* pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &pvk, pvk_len);

    if (pkey == NULL) return -1;
    
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);

    BIO *bio = BIO_new_file(file_name, "w");
    if (bio == NULL) return -2;    

    ret = PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);
    
    BIO_free_all(bio);
    
    return ret;
}
