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
    TEST_ASSERT_EQUAL_INT(0, -1);
}

void test_cb_kx_svr_session_keys()
{
    TEST_ASSERT_EQUAL_INT(0, -1);
}

void test_cb_kx_clt_session_keys()
{
    TEST_ASSERT_EQUAL_INT(0, -1);
}
