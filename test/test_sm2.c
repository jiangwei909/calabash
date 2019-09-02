#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include "calabash.h"
#include "unity/unity.h"

#include "test_sm2.h"

void test_cb_sm2_keypair()
{

    char pk[CB_SM2_PUBLICKEY_BYTES] = { 0x0 };
    char sk[CB_SM2_SECRETKEY_BYTES] = { 0x0 };
    int ret = -1;

    ret = cb_sm2_keypair(pk, sk);

    TEST_ASSERT_EQUAL_INT(0, ret);

}

void test_cb_sm2_encrypt()
{
    char *pk = "0492F775BC22B55B8CCBD2B8BE78E9F64D6AA74283C3A5127F8A50DEE107456A7FE28E2A15C219408FE05147A8C968FD88D7A88179530F1D836392C00A4B484DCD";
    char *plain = "123456781234567812345678123456781234567812345678";
    // char *plain = "ABCDEF0112345678";

    char cipher[256] = { 0x0 };
    int cipher_len = 256;
    
    char cipher_hex[8192] = { 0x0 };
    int cipher_hex_len;
    int ret = -1;

    char puk_bin[128] = { 0x0 };
    int puk_bin_len = 0;

    hex_to_bin(pk, strlen(pk), puk_bin, &puk_bin_len);
    
    ret = cb_sm2_encrypt(puk_bin, plain, strlen(plain), cipher);

    //char cipher_hex[8192] = { 0x0 };
    cb_bin_to_hex(cipher, ret, cipher_hex);

    printf("cipher len=%d cipher=%s\n", ret, cipher_hex);

    TEST_ASSERT_EQUAL_INT(144, ret);

}

void test_cb_sm2_decrypt()
{
    char* sk="74F3D6BCC82D29819BC9D9445210B3C581373715E3D728A54580B675C3CD6620";
    char *cipher = "2638566B3F9C15C5AD50C761DC7D101D348646BBD2E460399C743601CBB391AC6565E312433BF44FF1485529C74FE5455BDEF246263575FD756441DE74D25C7A125777432229DFAE221EA66EFA283D4B98577A5D5D2C397E212BE74C13FCC63F5A6BB8AEBCD316D6E7B94467E41055260EEDAD86BC6BD7AEC2AB2AAA738C1B3675076145BAA22B65C0C73D4A933EC591";
    char *expected_plain = "123456781234567812345678123456781234567812345678";
    int plain_len = 0;
    
    char cipher_hex[8192] = { 0x0 };
    int cipher_hex_len;
    int ret = -1;

    char cipher_bin[256] = { 0x0 };
    int cipher_bin_len;
    char plain[128] = { 0x0 };
    char pvk_bin[128] = { 0x0 };
    int pvk_bin_len = 0;

    hex_to_bin(sk, strlen(sk), pvk_bin, &pvk_bin_len);
    hex_to_bin(cipher, strlen(cipher), cipher_bin, &cipher_bin_len);
    
    plain_len = cb_sm2_decrypt(pvk_bin, cipher_bin, cipher_bin_len, plain);
    TEST_ASSERT_EQUAL_INT(48, plain_len);

    TEST_ASSERT_EQUAL_STRING(expected_plain, plain);
}

void test_cb_sm2_compute_key()
{
    char* private_key = "74F3D6BCC82D29819BC9D9445210B3C581373715E3D728A54580B675C3CD6620";
    char* public_key = "0492F775BC22B55B8CCBD2B8BE78E9F64D6AA74283C3A5127F8A50DEE107456A7FE28E2A15C219408FE05147A8C968FD88D7A88179530F1D836392C00A4B484DCD";
    char key[32] = { 0x0 };

    char* private_key_2 = "338985976857799783B8E60E5A1B6341FD171A096F67B4409C310B6A076926F3";
    char* public_key_2 = "04115FD9436BF40BC8866AC3B0333C208E1050A30851FA1056CA3D3177E00B200502AAF7E3CB98B97F09688A2D3DF2FD1645FB195FEB480A6B1C6FC72C8CE2DD56";

    char pvk_bin[128] = { 0x0 };
    char puk_bin[128] = { 0x0 };
    char key_hex[128] = { 0x0 };
    char key2_hex[128] = { 0x0 };
    char key2[32] = { 0x0 };

    cb_hex_to_bin(private_key, strlen(private_key), pvk_bin);
    cb_hex_to_bin(public_key_2, strlen(public_key_2), puk_bin);

    int ret = cb_sm2_compute_key(pvk_bin, puk_bin, key);

    TEST_ASSERT_EQUAL_INT(32, ret);

    cb_bin_to_hex(key, ret, key_hex);
    cb_debug("key hex=%s", key_hex);

    memset(pvk_bin, 0, sizeof(pvk_bin));
    memset(puk_bin, 0, sizeof(puk_bin));

    cb_hex_to_bin(private_key_2, strlen(private_key_2), pvk_bin);
    cb_hex_to_bin(public_key, strlen(public_key), puk_bin);

    ret = cb_sm2_compute_key(pvk_bin, puk_bin, key2);
    cb_bin_to_hex(key2, ret, key2_hex);
    cb_debug("key2 hex=%s", key2_hex);

    TEST_ASSERT_EQUAL_INT(32, ret);
    TEST_ASSERT_EQUAL_STRING(key_hex, key2_hex);
}