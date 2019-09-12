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

#include "calabash/publicbox.h"
#include "calabash/utils.h"

#define CB_PUBLICBOX_SESSIONKEY_BYTES 16

int cb_publicbox_seal(const char* pk, const char* data, unsigned int data_len, char* cipher)
{
    char session_key[CB_PUBLICBOX_SESSIONKEY_BYTES] = { 0x0 };
    int len = 0;

    // 第一个字节高4位表示版本，低4位表示类型, 0x1表示采用公钥加密，0x2采用会话密钥加密
    if (data_len > 256) {
        cipher[0] = 0x82;
    } else {
        cipher[0] = 0x81; 
        return 1 + cb_sm2_encrypt(pk, data, data_len, cipher + 1);
    }

    len += 1;
    
    RAND_bytes(session_key, CB_PUBLICBOX_SESSIONKEY_BYTES);

    // session key 加密数据
    len += cb_secretbox_easy(session_key, data, data_len, cipher + 1);

    // 加密 session key
    len += cb_sm2_encrypt(pk, session_key, CB_PUBLICBOX_SESSIONKEY_BYTES, cipher + len);

    return len;
}

int cb_publicbox_seal_open(const char* sk, const char* data, unsigned int data_len, char* plain)
{
    int len = 0;
    int ret = 0;
    int session_key_offset = 0;
    char session_key[CB_PUBLICBOX_SESSIONKEY_BYTES] = { 0x0 };
    
    if ((data[0] &0xff) == 0x81) {
        return  cb_sm2_decrypt(sk, data + 1, data_len - 1, plain);
    } else if ((data[0] &0xff) == 0x82) {
        // step 1, 解密会话密钥, 会话密钥由公钥加密后的长度是112
        session_key_offset = data_len - 112;

        ret = cb_sm2_decrypt(sk, data + session_key_offset, 112, session_key);
    
        if (ret != CB_PUBLICBOX_SESSIONKEY_BYTES) return -1;

        // step 2, 解密数据,去掉头部信息
        len = cb_secretbox_open_easy(session_key, data + 1, data_len - 1 - 112, plain);
    }

    return len;
}
