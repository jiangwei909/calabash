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
#include <openssl/des.h>

#include "calabash.h"
#include "calabash/utils.h"

static inline int des_ecb_crypt(const char* key, unsigned int key_len, const char* in_data, int in_data_len, char* out_data, int enc_type)
{
    DES_key_schedule ks1,ks2,ks3;
    
    char key_block[8] = { 0x0 };
    int out_data_len = 0;
    
    if (key_len % 8 != 0 || key_len > 24) return -1;
    if (in_data_len % 8 != 0) return -2;

    memcpy(key_block, key, 8);
    DES_set_key_unchecked((const_DES_cblock*)key_block, &ks1); 

    if (key_len >= 16) {
	memcpy(key_block, key+8, 8);
	DES_set_key_unchecked((const_DES_cblock*)key_block, &ks2);
    }

    if (key_len >= 24) {
	memcpy(key_block, key+16, 8);
	DES_set_key_unchecked((const_DES_cblock*)key_block, &ks3);
    }

    for (int i = 0; i < in_data_len / 8; i++) {
	switch (key_len) {
	case 8:
	    DES_ecb_encrypt((const_DES_cblock*)(in_data + i*8), (DES_cblock*)(out_data + i*8), &ks1, enc_type);
	    break;
	case 16:
	    DES_ecb2_encrypt((const_DES_cblock*)(in_data + i*8), (DES_cblock*)(out_data + i*8), &ks1, &ks2, enc_type);
	      break;
	case 24:
	    DES_ecb3_encrypt((const_DES_cblock*)(in_data + i*8), (DES_cblock*)(out_data + i*8), &ks1, &ks2, &ks3, enc_type);
	      break;
	}
	out_data_len += 8;
    }
    
    return out_data_len;
}


int des_ecb_encrypt(const char* key, unsigned int key_len, const char* plain, int plain_len, char* cipher)
{
    return des_ecb_crypt(key, key_len, plain, plain_len, cipher, 1);
}


int des_ecb_decrypt(const char* key, unsigned int key_len, const char* cipher, int cipher_len, char* plain)
{
    return des_ecb_crypt(key, key_len, cipher, cipher_len, plain, 0);
}

static inline int des_cbc_crypt(const char* key, unsigned int key_len, const char* iv, const char* in_data, int in_data_len, char* out_data, int enc_type)
{
    DES_key_schedule ks1,ks2,ks3;
    
    char key_block[8] = { 0x0 };
    int out_data_len = 0;
    
    if (key_len % 8 != 0 || key_len > 24) return -1;
    if (in_data_len % 8 != 0) return -2;

    memcpy(key_block, key, 8);
    DES_set_key_unchecked((const_DES_cblock*)key_block, &ks1); 

    if (key_len >= 16) {
	memcpy(key_block, key+8, 8);
	DES_set_key_unchecked((const_DES_cblock*)key_block, &ks2);
    }

    if (key_len >= 24) {
	memcpy(key_block, key+16, 8);
	DES_set_key_unchecked((const_DES_cblock*)key_block, &ks3);
    }

    switch (key_len) {
    case 8:
	DES_ncbc_encrypt(in_data, out_data, in_data_len, &ks1, (DES_cblock*)iv, enc_type);
	break;
    case 16:
	DES_ede2_cbc_encrypt(in_data, out_data, in_data_len, &ks1, &ks2, (DES_cblock*)iv, enc_type);
	break;
    case 24:
	DES_ede3_cbc_encrypt(in_data, out_data, in_data_len, &ks1, &ks2, &ks3, (DES_cblock*)iv, enc_type);
	break;
    }

    out_data_len = in_data_len;
    
    return out_data_len;
}

int des_cbc_encrypt(const char* key, unsigned int key_len, const char* iv, const char* plain, int plain_len, char* cipher)
{
    return des_cbc_crypt(key, key_len, iv, plain, plain_len, cipher, 1);
}


int des_cbc_decrypt(const char* key, unsigned int key_len, const char* iv, const char* cipher, int cipher_len, char* plain)
{
    return des_cbc_crypt(key, key_len, iv, cipher, cipher_len, plain, 0);
}
