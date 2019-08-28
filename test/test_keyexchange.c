#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include "calabash.h"
#include "unity/unity.h"

#include "test_keyexchange.h"

void test_cb_kx_keypair()
{
    char pk[CB_KX_PUBLICKEY_BYTES] = { 0x0 };
    char sk[CB_KX_SECRETKEY_BYTES] = { 0x0 };
    int ret = -1;

    ret = cb_kx_keypair(pk, sk);

    TEST_ASSERT_EQUAL_INT(0, ret);
}

void test_cb_kx_random_bufpair()
{
    char* pk = "0492F775BC22B55B8CCBD2B8BE78E9F64D6AA74283C3A5127F8A50DEE107456A7FE28E2A15C219408FE05147A8C968FD88D7A88179530F1D836392C00A4B484DCD";
    char rnd[CB_KX_RANDOM_BYTES] = { 0x0 };
    char pk_rnd[CB_KX_PK_RANDOM_BYTES] = { 0x0 };
    char puk_bin[256] = { 0x0 };
    int puk_bin_len = 0;

    hex_to_bin(pk, strlen(pk), puk_bin, &puk_bin_len);

    int ret = cb_kx_random_bufpair(puk_bin, rnd, pk_rnd);
    TEST_ASSERT_EQUAL_INT(0, ret);
}

void test_cb_kx_svr_session_keys()
{
    char* sk = "74F3D6BCC82D29819BC9D9445210B3C581373715E3D728A54580B675C3CD6620";
    char sk_bin[256] = { 0x0 };
    int sk_bin_len = 0;

    char* rx_rnd = "12345678ABCDEF01";
    //char* pk_tx_rnd_hex = "303F5F0D4EEEEE60D6ACFB679678A52A446E4BAF6477B577B6FB7C7393CC3AB3CBA3014890BCB239ECB7885B64FCC1CCF2BC82537EB353EEC534FCDD93931F75F128F1D2FF3EDFEF9D6E062D6605C3EFBCEF555C6517FACC2BD59FA562B90C85F72676CCC747D866AE69B1BBDC458D10";
    char* pk_tx_rnd_hex = "50E7FC5AB0662F53049C4C6A7291E1BBDE4A7F342188AFA4EB3937BAE236CA0A842A579500B70B42F8BB9652FD73FD792CFD8E9BE3E979B1737416F933E6560E07EFD729DC5CBA4EFA1CE9FB59C5D445E787EA0C882F801F473507E025124AAC5DBE80F7998FB751C17A5A344D0965EC";
    char pk_tx_rnd[CB_KX_PK_RANDOM_BYTES] = { 0x0 };

    char rx_key[CB_KX_SESSIONKEY_BYTES] = { 0x0 };
    char tx_key[CB_KX_SESSIONKEY_BYTES] = { 0x0 };
    char* expected_rx_key = "A80DC177593A837C632AD94762ED30AF";
    char* expected_tx_key = "750083D8C43C1C36EA240C15774CCD17";

    cb_hex_to_bin(sk, strlen(sk), sk_bin);
    cb_hex_to_bin(pk_tx_rnd_hex, strlen(pk_tx_rnd_hex), pk_tx_rnd);

    int ret = cb_kx_svr_session_keys(sk_bin, rx_rnd, pk_tx_rnd, tx_key, rx_key);


    TEST_ASSERT_EQUAL_INT(0, ret);

    char rx_key_hex[CB_KX_SESSIONKEY_BYTES*3] = { 0x0 };
    char tx_key_hex[CB_KX_SESSIONKEY_BYTES*3] = { 0x0 };

    cb_bin_to_hex(rx_key, CB_KX_SESSIONKEY_BYTES, rx_key_hex);
    cb_bin_to_hex(tx_key, CB_KX_SESSIONKEY_BYTES, tx_key_hex);

    TEST_ASSERT_EQUAL_STRING(expected_rx_key, rx_key_hex);
    TEST_ASSERT_EQUAL_STRING(expected_tx_key, tx_key_hex);

}

void test_cb_kx_clt_session_keys()
{
    char* rx_rnd = "12345678ABCDEF01";
    char* tx_rnd = "ABCDEF0112345678";
    char rx_key[CB_KX_SESSIONKEY_BYTES] = { 0x0 };
    char tx_key[CB_KX_SESSIONKEY_BYTES] = { 0x0 };
    char* expected_rx_key = "A80DC177593A837C632AD94762ED30AF";
    char* expected_tx_key = "750083D8C43C1C36EA240C15774CCD17";


    int ret = cb_kx_clt_session_keys(rx_rnd, tx_rnd, rx_key, tx_key);

    TEST_ASSERT_EQUAL_INT(0, ret);

    char rx_key_hex[CB_KX_SESSIONKEY_BYTES*3] = { 0x0 };
    char tx_key_hex[CB_KX_SESSIONKEY_BYTES*3] = { 0x0 };

    cb_bin_to_hex(rx_key, CB_KX_SESSIONKEY_BYTES, rx_key_hex);
    cb_bin_to_hex(tx_key, CB_KX_SESSIONKEY_BYTES, tx_key_hex);

    TEST_ASSERT_EQUAL_STRING(expected_rx_key, rx_key_hex);
    TEST_ASSERT_EQUAL_STRING(expected_tx_key, tx_key_hex);
    
}
