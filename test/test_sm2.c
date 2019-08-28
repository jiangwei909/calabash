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