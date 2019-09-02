#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include "calabash.h"
#include "unity/unity.h"

#include "test_kdf.h"

void test_cb_kdf_derive_from_key()
{
    char* master_key = "0123456789ABCDEF";
    unsigned int subkey_id = 0x1;
    char* context = "OK";
    unsigned int subkey_size = 64;
    char subkey[64] = { 0x0 };
    char subkey_hex[128] = { 0x0 };

    int ret = cb_kdf_derive_from_key(master_key, subkey_id, context, subkey_size, subkey);

    cb_bin_to_hex(subkey, subkey_size, subkey_hex);
    printf("subkey=%s\n", subkey_hex);

    TEST_ASSERT_EQUAL_INT(0, ret);
}