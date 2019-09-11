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

#include "calabash/secretbox.h"
#include "calabash/utils.h"
#include "calabash/sm4.h"

#define CB_SECRETBOX_MACKEY_ID 0x2
#define CB_SECRETBOX_DERIVATION_CONTENT "012345678"

// 按PKCS 5/7 的方式进行填充
static inline int pkcs_pad_data(char* data, int data_len, int block_size)
{
    int padding_len = block_size - data_len % block_size;
    for(int i = 0; i< padding_len; i++) {
        data[data_len + i] = (padding_len &0xff);
    }

    return padding_len;
}

void cb_secretbox_keygen(char* key)
{
    RAND_bytes(key, CB_SECRETBOX_KEY_BYTES);
}

int cb_secretbox_easy(const char* sk, const char* data, unsigned int data_len, char* cipher)
{
    char* plain = NULL;
    int plain_len = 0;
    unsigned int padding_len = 0;
    char iv[CB_SM4_KEY_BYTES] = { 0x0 };
    char mac_iv[CB_SM4_KEY_BYTES] = { 0x0 };
    char digest[32] = { 0x0 };
    char mac[16] = { 0x0};
    char mackey[CB_SECRETBOX_KEY_BYTES] = { 0x0};
    int ret = 0;
    
    // 按最大长度分配内存
    plain = malloc(data_len + CB_SECRETBOX_NONCE_BYTES + CB_SECRETBOX_BLOCK_BYTES);

    // 添加随机数当做头部
    RAND_bytes(plain, CB_SECRETBOX_NONCE_BYTES);
    memcpy(plain + CB_SECRETBOX_NONCE_BYTES, data, data_len);

    // 填充
    padding_len = pkcs_pad_data(plain, CB_SECRETBOX_NONCE_BYTES + data_len, CB_SECRETBOX_BLOCK_BYTES);
    plain_len = CB_SECRETBOX_NONCE_BYTES + data_len + padding_len;

    int cipher_len = cb_sm4_cbc_encrypt(sk, iv, plain, plain_len, cipher);
    if (cipher_len < 0) {
	ret =  -1;
	goto end;
    }
    
    // 计算MAC key
    cb_kdf_derive_from_key(sk, CB_SECRETBOX_MACKEY_ID, CB_SECRETBOX_DERIVATION_CONTENT, CB_SECRETBOX_KEY_BYTES, mackey);

    // 计算MAC
    cb_sm3_digest(cipher, cipher_len, digest);
    cb_sm4_mac(mackey, mac_iv, digest, 32, mac);

    memcpy(cipher + cipher_len, mac, 16);

    ret = plain_len + CB_SECRETBOX_CBCMAC_BYTES;
  end:
    free(plain);
    
    return ret;
}

int cb_secretbox_open_easy(const char* sk, const char* data, unsigned int data_len, char* plain)
{
    char* tmp_plain = NULL;
    unsigned int padding_len = 0;
    char iv[CB_SM4_KEY_BYTES] = { 0x0 };
    char mac_iv[CB_SM4_KEY_BYTES] = { 0x0 };
    char digest[32] = { 0x0 };
    char mac[16] = { 0x0};
    unsigned int plain_len = 0;
    char mackey[CB_SECRETBOX_KEY_BYTES] = { 0x0};
    int ret = 0;
    
    // step 1, verify mac
    //  计算MAC key
    cb_kdf_derive_from_key(sk, CB_SECRETBOX_MACKEY_ID, CB_SECRETBOX_DERIVATION_CONTENT, CB_SECRETBOX_KEY_BYTES, mackey);

    cb_sm3_digest(data, data_len - CB_SECRETBOX_CBCMAC_BYTES, digest);

    if (cb_sm4_mac_verify(mackey, mac_iv, digest, 32, data + data_len - CB_SECRETBOX_CBCMAC_BYTES) != 0 ) {
        return -2;
    }

    // step 2, decrypt
    tmp_plain = malloc(data_len);
    int tmp_plain_len = cb_sm4_cbc_decrypt(sk, iv, data, data_len - CB_SECRETBOX_CBCMAC_BYTES, tmp_plain);

    if (tmp_plain_len < 0) {
	ret = -1;
	goto end;
    }
    
    // step 3, erase header and padding
    padding_len = tmp_plain[tmp_plain_len - 1];

    plain_len = tmp_plain_len - 8 - padding_len;

    // step 4
    memcpy(plain, tmp_plain + 8, plain_len);
    ret = plain_len;
    
  end:
    free(tmp_plain);

    return ret;
}

int cb_secretbox_auth(const char* sk, const char* data, unsigned int data_len, char* mac)
{
    int md_len = 0;
    
    HMAC(EVP_sm3(), sk, CB_SECRETBOX_KEY_BYTES, data, data_len, mac, &md_len);

    return md_len;
}

int cb_secretbox_auth_verify(const char* sk, const char* data, unsigned int data_len, const char* mac)
{
    int md_len = 0;
    char actual_mac[32] = { 0x0 };

    //sm3_hmac(data, data_len, sk, CB_SECRETBOX_KEY_BYTES, actual_mac);
    HMAC(EVP_sm3(), sk, CB_SECRETBOX_KEY_BYTES, data, data_len, actual_mac, &md_len);
    
    for(int i = 0; i< 32; i++) {
        if (actual_mac[i] != mac[i]) return -1;
    }

    return 0;
}
