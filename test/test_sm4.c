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