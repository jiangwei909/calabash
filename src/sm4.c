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

#include "calabash/sm4.h"
#include "calabash/utils.h"


int cb_sm4_ecb_encrypt(const char* key, const char* plain, int plain_len, char* cipher)
{
    /*
    sms4_key_t sm4_key;
    
    sms4_set_encrypt_key(&sm4_key, key);

    for (int i = 0; i < plain_len / 16; i++) {
	sms4_encrypt(plain + i*16, cipher + i*16, &sm4_key);
    }
    
    return plain_len;
    */
   return -1;
}


int cb_sm4_ecb_decrypt(const char* key, const char* cipher, int cipher_len, char* plain)
{
    // sms4_key_t sm4_key;
    
    // sms4_set_decrypt_key(&sm4_key, key);

    // for (int i = 0; i < cipher_len / 16; i++) {
	// sms4_decrypt(cipher + i*16, plain + i*16, &sm4_key);
    // }
    
    // return cipher_len;
     return -1;
}

int cb_sm4_cbc_encrypt(const char* key, const char* iv, const char* plain, int plain_len, char* cipher)
{
    // sms4_key_t sm4_key;
    
    // sms4_set_encrypt_key(&sm4_key, key);

    // sms4_cbc_encrypt(plain, cipher, plain_len, &sm4_key, iv, 1);

    // return plain_len;
     return -1;
}

int cb_sm4_cbc_decrypt(const char* key, const char* iv, const char* cipher, int cipher_len, char* plain)
{
    // sms4_key_t sm4_key;
    
    // sms4_set_decrypt_key(&sm4_key, key);

    // sms4_cbc_encrypt(cipher, plain, cipher_len, &sm4_key, iv, 0);

    // return cipher_len;
     return -1;
}

int cb_sm4_mac(const char* key, const char* iv, const char* data, int data_len, char* mac)
{
    // unsigned int padding_len = 0;
    // char* plain = NULL;
    // char* cipher = NULL;
    // padding_len = 16 - data_len  % 16;

    // plain = malloc(data_len + 8 + padding_len);
    // cipher = malloc(data_len + 8 + padding_len);

    // memcpy(plain, data, data_len);
    // for(int i = 0; i< padding_len; i++) {
    //     if (i == 0) {
    //         plain[data_len + i] = 0x80;
    //     } else {
    //         plain[data_len + i] = 0x0;
    //     }
    // }

    // int cipher_len = cb_sm4_cbc_encrypt(key, iv, plain, data_len + padding_len, cipher);

    // memcpy(mac, cipher + cipher_len - 16, 16);

    // free(cipher);
    // free(plain);

    return 0;
}

int cb_sm4_mac_verify(const char* key, const char* iv, const char* data, int data_len, const char* mac)
{
    // char actual_mac[CB_SM4_MAC_BYTES] = { 0x0 };

    // cb_sm4_mac(key, iv, data, data_len, actual_mac);

    // for(int i = 0; i< CB_SM4_MAC_BYTES; i++) {
    //     if (actual_mac[i] != mac[i]) return -1;
    // }

    return 0;
}