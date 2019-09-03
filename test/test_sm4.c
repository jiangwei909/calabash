#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include "calabash.h"
#include "unity/unity.h"

#include "test_sm4.h"


void test_cb_sm4_mac()
{
    char* sk = "0123456789ABCDEF";
    char* data = "FECCADFDE058F9020178BA144F525505";
    int data_len = 0;
    data_len = strlen(data);
    char mac[CB_SM4_MAC_BYTES] = { 0x0 };
    char iv[CB_SM4_KEY_BYTES] = { 0x0 };
    char data_bin[40] = { 0x0 };
    char* expected_mac = "DA2FDA22E78180FF5831B071D246E403";
    char mac_hex[32] = {0x0 };

    cb_hex_to_bin(data, data_len, data_bin);

    int ret = cb_sm4_mac(sk, iv, data_bin, data_len/2, mac);

    cb_bin_to_hex(mac, CB_SM4_MAC_BYTES, mac_hex);

    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_STRING(expected_mac, mac_hex);
}

void test_cb_sm4_mac_verify()
{
    char* sk = "0123456789ABCDEF";
    char* data = "FECCADFDE058F9020178BA144F525505";
    int data_len = 0;
    data_len = strlen(data);
    char mac[CB_SM4_MAC_BYTES] = { 0x0 };
    char iv[CB_SM4_KEY_BYTES] = { 0x0 };
    char data_bin[40] = { 0x0 };
    char* expected_mac = "DA2FDA22E78180FF5831B071D246E403";


    cb_hex_to_bin(data, data_len, data_bin);
    cb_hex_to_bin(expected_mac, strlen(expected_mac), mac);

    int ret = cb_sm4_mac_verify(sk, iv, data_bin, data_len/2, mac);

    TEST_ASSERT_EQUAL_INT(0, ret);
}


void test_cb_sm4_cbc_encrypt()
{
    char* key = "0123456789ABCDEFFEDCBA9876543210";
    char* plain_hex = "0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210";
    char* expected_cipher_hex = "681EDF34D206965E86B3E94F536E42469FF11DCFD3AFAA236C76090BABC3BB85";
    
    char key_bin[32] = { 0x0 };
    char plain_bin[128] = { 0x0 };
    char cipher_bin[128] = { 0x0 };
    char cipher_hex[256] = { 0x0 };
    int plain_bin_len = 0;
    char iv[16] = { 0x0 };
    
    hex_to_bin(key, strlen(key), key_bin, NULL);
    hex_to_bin(plain_hex, strlen(plain_hex), plain_bin, &plain_bin_len);
    
    int ret = cb_sm4_cbc_encrypt(key_bin, iv, plain_bin, plain_bin_len, cipher_bin);
    
    TEST_ASSERT_EQUAL_INT(plain_bin_len, ret);
    
    bin_to_hex(cipher_bin, ret, cipher_hex, NULL);
    
    TEST_ASSERT_EQUAL_STRING(expected_cipher_hex, cipher_hex);
}

void test_cb_sm4_cbc_decrypt()
{
    char* key = "0123456789ABCDEFFEDCBA9876543210";
    char* expected_plain_hex = "0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210";
    char* cipher_hex = "681EDF34D206965E86B3E94F536E42469FF11DCFD3AFAA236C76090BABC3BB85";

    char key_bin[32] = { 0x0 };
    char plain_bin[128] = { 0x0 };
    char cipher_bin[128] = { 0x0 };

    char plain_hex[256] = { 0x0 };
    int plain_bin_len = 0;
    int cipher_bin_len = 0;
    char iv[16] = { 0x0 };
    
    hex_to_bin(key, strlen(key), key_bin, NULL);
    hex_to_bin(cipher_hex, strlen(cipher_hex), cipher_bin, &cipher_bin_len);
    
    int ret = cb_sm4_cbc_decrypt(key_bin, iv, cipher_bin, cipher_bin_len, plain_bin);    
    
    TEST_ASSERT_EQUAL_INT(cipher_bin_len, ret);
    
    bin_to_hex(plain_bin, ret, plain_hex, NULL);
    
    TEST_ASSERT_EQUAL_STRING(expected_plain_hex, plain_hex);
}

void test_cb_sm4_ecb_encrypt()
{
    char* key = "0123456789ABCDEFFEDCBA9876543210";
    char* plain_hex = "0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210";
    char* expected_cipher_hex = "681EDF34D206965E86B3E94F536E4246681EDF34D206965E86B3E94F536E4246";

    char key_bin[32] = { 0x0 };
    char plain_bin[128] = { 0x0 };
    char cipher_bin[128] = { 0x0 };
    char cipher_hex[256] = { 0x0 };
    int plain_bin_len = 0;
    
    hex_to_bin(key, strlen(key), key_bin, NULL);
    hex_to_bin(plain_hex, strlen(plain_hex), plain_bin, &plain_bin_len);
    
    int ret = cb_sm4_ecb_encrypt(key_bin, plain_bin, plain_bin_len, cipher_bin);    
    
    TEST_ASSERT_EQUAL_INT(plain_bin_len, ret);
    
    bin_to_hex(cipher_bin, ret, cipher_hex, NULL);
    
    TEST_ASSERT_EQUAL_STRING(expected_cipher_hex, cipher_hex);
}

void test_cb_sm4_ecb_decrypt()
{
    char* key = "0123456789ABCDEFFEDCBA9876543210";
    char* expected_plain_hex = "0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210";
    char* cipher_hex = "681EDF34D206965E86B3E94F536E4246681EDF34D206965E86B3E94F536E4246";

    char key_bin[32] = { 0x0 };
    char plain_bin[128] = { 0x0 };
    char cipher_bin[128] = { 0x0 };

    char plain_hex[256] = { 0x0 };
    int plain_bin_len = 0;
    int cipher_bin_len = 0;
    
    hex_to_bin(key, strlen(key), key_bin, NULL);
    hex_to_bin(cipher_hex, strlen(cipher_hex), cipher_bin, &cipher_bin_len);
    
    int ret = cb_sm4_ecb_decrypt(key_bin, cipher_bin, cipher_bin_len, plain_bin);    
    
    TEST_ASSERT_EQUAL_INT(cipher_bin_len, ret);
    
    bin_to_hex(plain_bin, ret, plain_hex, NULL);
    
    TEST_ASSERT_EQUAL_STRING(expected_plain_hex, plain_hex);
}