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

#include "calabash/pem.h"
#include "calabash/utils.h"


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
