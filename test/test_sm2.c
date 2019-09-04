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

void test_cb_sm2_compress_public_key()
{
    char *puk = "81bf68edf30e4ff2d57545703999d1df6edee63a1fc5f46c8fd768f2a4c2308bb328f1038af1295cbb1a4b29fc2e2ea0e05562e5058d8a94a703f03f9996327d";
    char *puk2 = "04c3b6d648e13b191c0cb6f754c994c369b5d0842c0e8f5af2e08f9e199ddbf5c88ea2675a7f784506714c29315b55307bd96a3a866566f703f4d86f072421018a";

    int ret = -1;
    char compressed_puk[128] = { 0x0 };
    int compressed_puk_len;
    char *excepted_puk = "0381BF68EDF30E4FF2D57545703999D1DF6EDEE63A1FC5F46C8FD768F2A4C2308B";
    char *excepted_puk2 = "02C3B6D648E13B191C0CB6F754C994C369B5D0842C0E8F5AF2E08F9E199DDBF5C8";

    char puk_bin[128] = { 0x0};
    int puk_bin_len;
    char puk_hex[128] = { 0x0};
    int puk_hex_len;

    hex_to_bin(puk, strlen(puk), puk_bin, &puk_bin_len);

    ret = cb_sm2_compress_public_key(puk_bin, puk_bin_len, compressed_puk);
    TEST_ASSERT_EQUAL_INT(0, ret);

    bin_to_hex(compressed_puk, CB_SM2_COMPRESS_PUBLICKEY_BYTES, puk_hex, &puk_bin_len);
    TEST_ASSERT_EQUAL_STRING(excepted_puk, puk_hex);

    //assert_string_equal(puk_hex, excepted_puk);

    hex_to_bin(puk2, strlen(puk2), puk_bin, &puk_bin_len);

    ret = cb_sm2_compress_public_key(puk_bin, puk_bin_len, compressed_puk);
    TEST_ASSERT_EQUAL_INT(0, ret);

    bin_to_hex(compressed_puk, CB_SM2_COMPRESS_PUBLICKEY_BYTES, puk_hex, &puk_bin_len);
    TEST_ASSERT_EQUAL_STRING(excepted_puk2, puk_hex);
}

void test_cb_sm2_uncompress_public_key()
{
    char *expected_puk = "0481BF68EDF30E4FF2D57545703999D1DF6EDEE63A1FC5F46C8FD768F2A4C2308BB328F1038AF1295CBB1A4B29FC2E2EA0E05562E5058D8A94A703F03F9996327D";
    char *expected_puk2 = "04C3B6D648E13B191C0CB6F754C994C369B5D0842C0E8F5AF2E08F9E199DDBF5C88EA2675A7F784506714C29315B55307BD96A3A866566F703F4D86F072421018A";

    int ret = 0;
    char uncompressed_puk[128] = { 0x0 };
    int uncompressed_puk_len;
    char *compress_puk = "0381BF68EDF30E4FF2D57545703999D1DF6EDEE63A1FC5F46C8FD768F2A4C2308B";
    // char *excepted_puk = "03176BC7E66ADBE66734A38A19F6901B1C9D7D90F6428BD08B58F075F934728D37";
    char *compress_puk2 = "02C3B6D648E13B191C0CB6F754C994C369B5D0842C0E8F5AF2E08F9E199DDBF5C8";

    char puk_bin[128] = { 0x0};
    int puk_bin_len;
    char puk_hex[144] = { 0x0};
    int puk_hex_len;

    cb_hex_to_bin(compress_puk, strlen(compress_puk), puk_bin);

    ret = cb_sm2_uncompress_public_key(puk_bin, uncompressed_puk);
    TEST_ASSERT_EQUAL_INT(0, ret);

    cb_bin_to_hex(uncompressed_puk, CB_SM2_PUBLICKEY_BYTES, puk_hex);

    //assert_int_equal(ret, 0);
    TEST_ASSERT_EQUAL_STRING(expected_puk, puk_hex);

    puk_bin_len = cb_hex_to_bin(compress_puk2, strlen(compress_puk2), puk_bin);

    ret = cb_sm2_uncompress_public_key(puk_bin, uncompressed_puk);
    TEST_ASSERT_EQUAL_INT(0, ret);

    cb_bin_to_hex(uncompressed_puk, CB_SM2_PUBLICKEY_BYTES, puk_hex);
    TEST_ASSERT_EQUAL_STRING(expected_puk2, puk_hex);
}


void test_cb_sm2_compute_puk()
{
    char puk[144] = { 0x0 };
    char* pvk = "74F3D6BCC82D29819BC9D9445210B3C581373715E3D728A54580B675C3CD6620";
    int pvk_len;
    int puk_len = 65;

    char puk_hex[512] = { 0x0};
    char pvk_hex[512] = { 0x0};
    int pvk_hex_len = 0;
    int puk_hex_len = 0;

    char pvk_bin[65] = { 0x0};
    int pvk_bin_len = 0;
    char* expected_puk_hex = "0492F775BC22B55B8CCBD2B8BE78E9F64D6AA74283C3A5127F8A50DEE107456A7FE28E2A15C219408FE05147A8C968FD88D7A88179530F1D836392C00A4B484DCD";
    
    int ret = -1;

    cb_hex_to_bin(pvk, 64, pvk_bin);
    
    ret = cb_sm2_compute_puk(pvk_bin, puk);
    TEST_ASSERT_EQUAL_INT(0, ret);

    cb_bin_to_hex(puk, puk_len, puk_hex);

    TEST_ASSERT_EQUAL_STRING(expected_puk_hex, puk_hex);
}

void test_cb_sm2_sign()
{
    char* pvk = "74F3D6BCC82D29819BC9D9445210B3C581373715E3D728A54580B675C3CD6620";
    char* puk = "92F775BC22B55B8CCBD2B8BE78E9F64D6AA74283C3A5127F8A50DEE107456A7FE28E2A15C219408FE05147A8C968FD88D7A88179530F1D836392C00A4B484DCD";
    char* message = "hello sm2";
    char *id = "1234567812345678";

    char pvk_bin[512] = {0x0};
    int pvk_bin_len;
    char signature[CB_SM2_SIGNATURE_BYTES] = {0x0};
    int signature_len = 0;

    char signature_hex[256] = {0x0};
    int signature_hex_len = 0;

    char message_hex[256] = {0x0};
    int message_hex_len = 0;

    cb_hex_to_bin(pvk, strlen(pvk), pvk_bin);

    int ret = cb_sm2_sign(pvk_bin, id, message, strlen(message), signature);

    TEST_ASSERT_EQUAL_INT(0, ret);

    cb_bin_to_hex(signature, CB_SM2_SIGNATURE_BYTES, signature_hex);
    printf("signature[%d] = %s\n", signature_len, signature_hex);

    ret = cb_sm2_sign(pvk_bin, NULL, message, strlen(message), signature);

    TEST_ASSERT_EQUAL_INT(0, ret);

}

void test_cb_sm2_sign_verify()
{
    char* puk = "0492F775BC22B55B8CCBD2B8BE78E9F64D6AA74283C3A5127F8A50DEE107456A7FE28E2A15C219408FE05147A8C968FD88D7A88179530F1D836392C00A4B484DCD";
    char* message = "hello sm2";

    char puk_bin[512] = {0x0};
    int puk_bin_len;
    unsigned char *signature = "CEDD27F1D28B2B9106AB8807A6F29172CDB563B8488681E0CF823A67D01301BDD0D7E17C8A1578876EA0955145A5F72EAFE36389BC73F41AB1650CBE3D9BFA59";
    int signature_len = 0;
    char *id = "1234567812345678";

    char signature_bin[256] = {0x0};
    int signature_bin_len = 0;

    char message_hex[256] = {0x0};
    int message_hex_len = 0;
    int ret = -1;

    hex_to_bin(puk, strlen(puk), puk_bin, &puk_bin_len);
    bin_to_hex(message, strlen(message), message_hex, &message_hex_len);
    hex_to_bin(signature, strlen(signature), signature_bin, &signature_bin_len);

    ret = cb_sm2_sign_verify(puk_bin, NULL, message, strlen(message), signature_bin);
    TEST_ASSERT_EQUAL_INT(0, ret);
}