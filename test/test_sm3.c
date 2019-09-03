#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include "calabash.h"
#include "unity/unity.h"

#include "test_sm3.h"

void test_cb_sm3_digest()
{
    char* data = "12345678";
    int ret = -1;
    char digest[128];
    int digest_len = -1;
    char* expected_digest = "0FFFFF81E971FA3F09107ABF77931463FC0710BFB8962EFEAE3D5654B073BB0C";
    char digest_hex[128] = { 0x0 };
    int digest_hex_len = 0;
    
    ret = cb_sm3_digest(data, strlen(data), digest);

    cb_bin_to_hex(digest, 32, digest_hex);
    
    TEST_ASSERT_EQUAL_INT(32, ret);
    TEST_ASSERT_EQUAL_STRING(expected_digest, digest_hex);
}