#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include "calabash.h"
#include "unity/unity.h"

#include "test_secretbox.h"

void test_cb_secretbox_keygen()
{
    char key[CB_SECRETBOX_KEY_BYTES] = { 0x0 };
    char key_hex[CB_SECRETBOX_KEY_BYTES*2] = { 0x0 };

    cb_secretbox_keygen(key);
    cb_bin_to_hex(key, CB_SECRETBOX_KEY_BYTES, key_hex);

    printf("key hex=%s\n", key_hex);

    TEST_ASSERT_EQUAL_INT(0, 0);
}

void test_cb_secretbox_easy()
{
    char* sk = "0123456789ABCDEF";
    char* data = "123";
    int data_len = 0;
    data_len = strlen(data);
    char cipher[40];
    char cipher_hex[80] = { 0x0 };

    int cipher_len = cb_secretbox_easy(sk, data, data_len, cipher);

    cb_bin_to_hex(cipher, cipher_len, cipher_hex);
    printf("cipher hex=%s\n", cipher_hex);

    TEST_ASSERT_EQUAL_INT(32, cipher_len);
}

void test_cb_secretbox_open_easy()
{
    char* sk = "0123456789ABCDEF";
    char* data = "6E4AFD3DF31C76D1923EB3255349BE8E85BE55E1C48538D54F648BD9902A3DBC";
    int data_len = 0;
    data_len = strlen(data);
    char plain[40] = { 0x0 };
    char cipher_hex[80] = { 0x0 };
    char data_bin[40] = { 0x0 };
    char* expected_plain = "123";

    cb_hex_to_bin(data, data_len, data_bin);

    int plain_len = cb_secretbox_open_easy(sk, data_bin, data_len/2, plain);
    TEST_ASSERT_EQUAL_INT(3, plain_len);
    TEST_ASSERT_EQUAL_STRING(expected_plain, plain);
}

void test_cb_secretbox_auth()
{
    char* sk = "0123456789ABCDEF";
    char* data = "6E4AFD3DF31C76D1923EB3255349BE8E9F18FEE8F9705EBFC4E53B5B87ACFD84";
    int data_len = 0;
    data_len = strlen(data);
    char mac[40] = { 0x0 };
    char mac_hex[80] = { 0x0 };
    char data_bin[40] = { 0x0 };

    int mac_len = cb_secretbox_auth(sk, data, data_len, mac);
    cb_bin_to_hex(mac, mac_len, mac_hex);
    printf("mac hex=%s\n", mac_hex);

    TEST_ASSERT_EQUAL_INT(CB_SECRETBOX_AUTHMAC_BYTES, mac_len);

}

void test_cb_secretbox_auth_verify()
{
    char* sk = "0123456789ABCDEF";
    char* data = "6E4AFD3DF31C76D1923EB3255349BE8E9F18FEE8F9705EBFC4E53B5B87ACFD84";
    int data_len = 0;
    data_len = strlen(data);
    char mac[40] = { 0x0 };
    char* mac_hex = "CD66BB3CCECC3EAD6043020F7E2DC0093DFCECC37599BBED0BA4B0B84AE1D18D";
    char data_bin[40] = { 0x0 };

    cb_hex_to_bin(mac_hex, strlen(mac_hex), mac);

    int ret = cb_secretbox_auth_verify(sk, data, data_len, mac);

    TEST_ASSERT_EQUAL_INT(0, ret);
}