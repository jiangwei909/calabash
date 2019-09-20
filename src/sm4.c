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


static inline int _do_cipher(EVP_CIPHER* cipher, int pad, int enc, const char* key,
			     const char* iv, const char* in, int inl, char* out)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int ret = 0;
    size_t out_len = 0;
    int total_len =0;
    
    ctx = EVP_CIPHER_CTX_new();

    cb_debug("in len=%d", inl);
    EVP_CipherInit(ctx, cipher, key, iv, enc);
    EVP_CIPHER_CTX_set_padding(ctx, pad);
    
    EVP_CipherUpdate(ctx, out, &out_len, in, inl);
    total_len += out_len; 
        
    EVP_CipherFinal(ctx, out + total_len, &out_len);
    total_len += out_len;
    cb_debug("out len=%d", total_len);
    
    return total_len;
}


int cb_sm4_ecb_encrypt(const char* key, const char* plain, int plain_len,
		       char* ciphertext)
{
    EVP_CIPHER *cipher = NULL;
    cipher = EVP_sm4_ecb();
    
    return _do_cipher(cipher, 0, 1, key, NULL, plain, plain_len, ciphertext);
}

int cb_sm4_ecb_decrypt(const char* key, const char* ciphertext, int ciphertext_len, char* plain)
{
    EVP_CIPHER *cipher = NULL;
    cipher = EVP_sm4_ecb();
    
    return _do_cipher(cipher, 0, 0, key, NULL, ciphertext, ciphertext_len, plain);    
}

int cb_sm4_cbc_encrypt(const char* key, const char* iv, const char* plain,
		       int plain_len, char* ciphertext)
{
    EVP_CIPHER *cipher = NULL;
    cipher = EVP_sm4_cbc();
    
    return _do_cipher(cipher, 0, 1, key, iv, plain, plain_len, ciphertext);
}

int cb_sm4_cbc_decrypt(const char* key, const char* iv, const char* ciphertext,
		       int ciphertext_len, char* plain)
{
    EVP_CIPHER *cipher = NULL;
    cipher = EVP_sm4_cbc();
    
    return _do_cipher(cipher, 0, 0, key, iv, ciphertext, ciphertext_len, plain);    
}

int cb_sm4_mac(const char* key, const char* iv, const char* data, int data_len, char* mac)
{
    unsigned int padding_len = 0;
    char* plain = NULL;
    char* cipher = NULL;

    if (data_len <= 0) return -1;
    
    padding_len = 16 - data_len  % 16;

    plain = malloc(data_len + 8 + padding_len);
    cipher = malloc(data_len + 8 + padding_len);

    memcpy(plain, data, data_len);
    for(int i = 0; i< padding_len; i++) {
        if (i == 0) {
            plain[data_len + i] = 0x80;
        } else {
            plain[data_len + i] = 0x0;
        }
    }

    int cipher_len = cb_sm4_cbc_encrypt(key, iv, plain, data_len + padding_len, cipher);

    // the last block is mac
    memcpy(mac, cipher + cipher_len - 16, 16);

    free(cipher);
    free(plain);

    return 0;
}

int cb_sm4_mac_verify(const char* key, const char* iv, const char* data, int data_len, const char* mac)
{
    char actual_mac[CB_SM4_MAC_BYTES] = { 0x0 };

    if (data_len <= 0) return -1; 
    
    cb_sm4_mac(key, iv, data, data_len, actual_mac);
    
    for(int i = 0; i< CB_SM4_MAC_BYTES; i++) {
        if (actual_mac[i] != mac[i]) return -2;
    }

    return 0;
}
