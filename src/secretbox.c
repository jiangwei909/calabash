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

#include "calabash/secretbox.h"
#include "calabash/utils.h"
#include "calabash/sm4.h"

void cb_secretbox_keygen(char* key)
{
    RAND_bytes(key, CB_SECRETBOX_KEY_BYTES);
}

int cb_secretbox_easy(const char* sk, const char* data, unsigned int data_len, char* cipher)
{
    char* plain = NULL;
    unsigned int padding_len = 0;
    char iv[CB_SM4_KEY_BYTES] = { 0x0 };
    char mac_iv[CB_SM4_KEY_BYTES] = { 0x0 };
    char digest[32] = { 0x0 };
    char mac[16] = { 0x0};

    padding_len = 16 - (data_len + 8) % 16;

    plain = malloc(data_len + 8 + padding_len);

    RAND_bytes(plain, 8);
    memcpy(plain + 8, data, data_len);
    for(int i = 0; i< padding_len; i++) {
        plain[8 + data_len + i] = (padding_len &0xff);
    }

    int cipher_len = cb_sm4_cbc_encrypt(sk, iv, plain, data_len + 8 + padding_len, cipher);

    memset(iv, 0x0, CB_SM4_KEY_BYTES);

    cb_sm3_digest(cipher, cipher_len, digest);

    cb_sm4_mac(sk, mac_iv, digest, 32, mac);

    memcpy(cipher + cipher_len, mac, 16);

    free(plain);

    return data_len + 8 + padding_len + 16;
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

    tmp_plain = malloc(data_len);

    // step 1, verify mac
    cb_sm3_digest(data, data_len - CB_SECRETBOX_MAC_BYTES, digest);

    if (cb_sm4_mac_verify(sk, mac_iv, digest, 32, data + data_len - CB_SECRETBOX_MAC_BYTES) != 0 ) {
        return -2;
    }

    // step 2, decrypt
    int tmp_plain_len = cb_sm4_cbc_decrypt(sk, iv, data, data_len - CB_SECRETBOX_MAC_BYTES, tmp_plain);

    // step 3, erase header and padding
    padding_len = tmp_plain[tmp_plain_len - 1];

    plain_len = tmp_plain_len - 8 - padding_len;

    // step 4
    memcpy(plain, tmp_plain + 8, plain_len);

    free(tmp_plain);

    return plain_len;
}

int cb_secretbox_auth(const char* sk, const char* data, unsigned int data_len, char* mac)
{

    sm3_hmac(data, data_len, sk, CB_SECRETBOX_KEY_BYTES, mac);

    return SM3_HMAC_SIZE;
}

int cb_secretbox_auth_verify(const char* sk, const char* data, unsigned int data_len, const char* mac)
{
    char actual_mac[SM3_HMAC_SIZE] = { 0x0 };

    sm3_hmac(data, data_len, sk, CB_SECRETBOX_KEY_BYTES, actual_mac);

    for(int i = 0; i< SM3_HMAC_SIZE; i++) {
        if (actual_mac[i] != mac[i]) return -1;
    }

    return 0;
}