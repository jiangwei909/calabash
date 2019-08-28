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
    TEST_ASSERT_EQUAL_INT(0, -1);
}

void test_cb_kx_clt_session_keys()
{
    TEST_ASSERT_EQUAL_INT(0, -1);
}
