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

#include "calabash/sm4.h"
#include "calabash/utils.h"


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
