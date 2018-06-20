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

int rsa_read_puk_from_pem_file(const char* pemfile, char* puk)
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
	memcpy(puk, buff, buff_len);
	ret = buff_len;
    } else {
	printf("WARNING: This is not a valid pem key file.\n");
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
