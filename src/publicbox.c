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
#include <openssl/gmapi.h>
#include <openssl/sms4.h>

#include "calabash/publicbox.h"
#include "calabash/utils.h"

int cb_publicbox_seal(const char* pk, const char* data, unsigned int data_len, char* cipher)
{
    cipher[0] = 0x1;

    return 1 + cb_sm2_encrypt(pk, data, data_len, cipher + 1);

}

int cb_publicbox_seal_open(const char* sk, const char* data, unsigned int data_len, char* plain)
{
    return  cb_sm2_decrypt(sk, data + 1, data_len - 1, plain);
}