//
// Created by jiangwei on 2017/11/29.
//

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include "calabash.h"
#include "unity/unity.h"

void test_sm2_compress_public_key()
{
    char *puk = "81bf68edf30e4ff2d57545703999d1df6edee63a1fc5f46c8fd768f2a4c2308bb328f1038af1295cbb1a4b29fc2e2ea0e05562e5058d8a94a703f03f9996327d";
    char *puk2 = "04c3b6d648e13b191c0cb6f754c994c369b5d0842c0e8f5af2e08f9e199ddbf5c88ea2675a7f784506714c29315b55307bd96a3a866566f703f4d86f072421018a";

    int ret = 0;
    char compressed_puk[128] = { 0x0 };
    int compressed_puk_len;
    char *excepted_puk = "0381BF68EDF30E4FF2D57545703999D1DF6EDEE63A1FC5F46C8FD768F2A4C2308B";
    char *excepted_puk2 = "02C3B6D648E13B191C0CB6F754C994C369B5D0842C0E8F5AF2E08F9E199DDBF5C8";

    char puk_bin[128] = { 0x0};
    int puk_bin_len;
    char puk_hex[128] = { 0x0};
    int puk_hex_len;

    hex_to_bin(puk, strlen(puk), puk_bin, &puk_bin_len);

    ret = sm2_compress_public_key(puk_bin, puk_bin_len, compressed_puk, &compressed_puk_len);
    TEST_ASSERT_EQUAL_INT(0, ret);

    bin_to_hex(compressed_puk, compressed_puk_len, puk_hex, &puk_bin_len);
    TEST_ASSERT_EQUAL_STRING(excepted_puk, puk_hex);

    //assert_string_equal(puk_hex, excepted_puk);

    hex_to_bin(puk2, strlen(puk2), puk_bin, &puk_bin_len);

    ret = sm2_compress_public_key(puk_bin, puk_bin_len, compressed_puk, &compressed_puk_len);
    TEST_ASSERT_EQUAL_INT(0, ret);

    bin_to_hex(compressed_puk, compressed_puk_len, puk_hex, &puk_bin_len);
    TEST_ASSERT_EQUAL_STRING(excepted_puk2, puk_hex);
}

void test_uncompress_public_key()
{
    char *puk = "0481BF68EDF30E4FF2D57545703999D1DF6EDEE63A1FC5F46C8FD768F2A4C2308BB328F1038AF1295CBB1A4B29FC2E2EA0E05562E5058D8A94A703F03F9996327D";
    char *puk2 = "04C3B6D648E13B191C0CB6F754C994C369B5D0842C0E8F5AF2E08F9E199DDBF5C88EA2675A7F784506714C29315B55307BD96A3A866566F703F4D86F072421018A";

    int ret = 0;
    char uncompressed_puk[128] = { 0x0 };
    int uncompressed_puk_len;
    char *excepted_puk = "0381BF68EDF30E4FF2D57545703999D1DF6EDEE63A1FC5F46C8FD768F2A4C2308B";
    char *excepted_puk2 = "02C3B6D648E13B191C0CB6F754C994C369B5D0842C0E8F5AF2E08F9E199DDBF5C8";

    char puk_bin[128] = { 0x0};
    int puk_bin_len;
    char puk_hex[144] = { 0x0};
    int puk_hex_len;

    hex_to_bin(excepted_puk, strlen(excepted_puk), puk_bin, &puk_bin_len);

    ret = sm2_uncompress_public_key(puk_bin, puk_bin_len, uncompressed_puk, &uncompressed_puk_len);
    TEST_ASSERT_EQUAL_INT(0, ret);

    bin_to_hex(uncompressed_puk, uncompressed_puk_len, puk_hex, &puk_bin_len);

    //assert_int_equal(ret, 0);
    TEST_ASSERT_EQUAL_STRING(puk, puk_hex);

    hex_to_bin(excepted_puk2, strlen(excepted_puk2), puk_bin, &puk_bin_len);

    ret = sm2_uncompress_public_key(puk_bin, puk_bin_len, uncompressed_puk, &uncompressed_puk_len);
    TEST_ASSERT_EQUAL_INT(0, ret);

    bin_to_hex(uncompressed_puk, uncompressed_puk_len, puk_hex, &puk_bin_len);
    TEST_ASSERT_EQUAL_STRING(puk2, puk_hex);
}

void test_sm2_sign_with_pem()
{
    char* pvk = "3077020101042074F3D6BCC82D29819BC9D9445210B3C581373715E3D728A54580B675C3CD6620A00A06082A811CCF5501822DA1440342000492F775BC22B55B8CCBD2B8BE78E9F64D6AA74283C3A5127F8A50DEE107456A7FE28E2A15C219408FE05147A8C968FD88D7A88179530F1D836392C00A4B484DCD";
    char* puk = "92F775BC22B55B8CCBD2B8BE78E9F64D6AA74283C3A5127F8A50DEE107456A7FE28E2A15C219408FE05147A8C968FD88D7A88179530F1D836392C00A4B484DCD";
    char* message = "hello sm2";

    char pvk_bin[512] = {0x0};
    int pvk_bin_len;
    char signature[128] = {0x0};
    int signature_len = 0;

    char signature_hex[256] = {0x0};
    int signature_hex_len = 0;

    char message_hex[256] = {0x0};
    int message_hex_len = 0;

    hex_to_bin(pvk, strlen(pvk), pvk_bin, &pvk_bin_len);
    bin_to_hex(message, strlen(message), message_hex, &message_hex_len);

    printf("message hex = %s\n", message_hex);

    sm2_sign_with_pem(pvk_bin, pvk_bin_len, message, strlen(message), signature, &signature_len);

    bin_to_hex(signature, signature_len, signature_hex, &signature_hex_len);
    printf("signature[%d] = %s\n", signature_len, signature_hex);

}

void test_sm2_sign()
{
    char* pvk = "74F3D6BCC82D29819BC9D9445210B3C581373715E3D728A54580B675C3CD6620";
    char* puk = "92F775BC22B55B8CCBD2B8BE78E9F64D6AA74283C3A5127F8A50DEE107456A7FE28E2A15C219408FE05147A8C968FD88D7A88179530F1D836392C00A4B484DCD";
    char* message = "hello sm2";

    char pvk_bin[512] = {0x0};
    int pvk_bin_len;
    char signature[128] = {0x0};
    int signature_len = 0;

    char signature_hex[256] = {0x0};
    int signature_hex_len = 0;

    char message_hex[256] = {0x0};
    int message_hex_len = 0;

    hex_to_bin(pvk, strlen(pvk), pvk_bin, &pvk_bin_len);
    bin_to_hex(message, strlen(message), message_hex, &message_hex_len);

    printf("message hex = %s\n", message_hex);

    sm2_sign(pvk_bin, pvk_bin_len, message, strlen(message), signature, &signature_len);

    bin_to_hex(signature, signature_len, signature_hex, &signature_hex_len);
    printf("signature[%d] = %s\n", signature_len, signature_hex);

}

void test_sm2_sign_verify()
{
    char* puk = "92F775BC22B55B8CCBD2B8BE78E9F64D6AA74283C3A5127F8A50DEE107456A7FE28E2A15C219408FE05147A8C968FD88D7A88179530F1D836392C00A4B484DCD";
    char* message = "hello sm2";

    char puk_bin[512] = {0x0};
    int puk_bin_len;
    unsigned char *signature = "CEDD27F1D28B2B9106AB8807A6F29172CDB563B8488681E0CF823A67D01301BDD0D7E17C8A1578876EA0955145A5F72EAFE36389BC73F41AB1650CBE3D9BFA59";
    int signature_len = 0;

    char signature_bin[256] = {0x0};
    int signature_bin_len = 0;

    char message_hex[256] = {0x0};
    int message_hex_len = 0;
    int ret;

    hex_to_bin(puk, strlen(puk), puk_bin, &puk_bin_len);
    bin_to_hex(message, strlen(message), message_hex, &message_hex_len);
    hex_to_bin(signature, strlen(signature), signature_bin, &signature_bin_len);

    printf("message hex = %s\n", message_hex);

    ret = sm2_sign_verify(puk_bin, puk_bin_len, message, strlen(message), signature_bin, signature_bin_len);
    printf("ret = %d\n", ret);

    //assert_int_equal(ret, 0);
}

void test_sm2_sign_verify_2()
{
    unsigned char* puk = "359D85951D925C8B4075A2109CAD866C156E3DD977D436FBCF3C8CA035753D4F1C8F96341F1FEB776C9050342231AD0531CC2591425FD92C24A24C3616031731";
    char* message_hex = "230101000002111700000204040040359D85951D925C8B4075A2109CAD866C156E3DD977D436FBCF3C8CA035753D4F1C8F96341F1FEB776C9050342231AD0531CC2591425FD92C24A24C3616031731";

    unsigned char puk_bin[512] = {0x0};
    int puk_bin_len;
    unsigned char *signature = "83F75144BC20623850AFB66FFDB2B60FF91A19D5688AAC50386A14F6AD67244B5F57F01ED43B86421FEAA7D3569D556DE9910E2E15B865CC3104B2AC9256AF10";
    int signature_len = 0;

    unsigned char signature_bin[256] = {0x0};
    int signature_bin_len = 0;

    unsigned char message_bin[256] = {0x0};
    int message_bin_len = 0;
    int ret;

    hex_to_bin(puk, strlen(puk), puk_bin, &puk_bin_len);
    hex_to_bin(message_hex, strlen(message_hex), message_bin, &message_bin_len);
    hex_to_bin(signature, strlen(signature), signature_bin, &signature_bin_len);

    printf("message hex = %s\n", message_hex);

    printf("PUK BIN= ");
    for(int i = 0; i< puk_bin_len; i++) {
        printf("%02X", puk_bin[i]);
    }
    printf("\n");

    printf("message_bin= ");
    for(int i = 0; i< message_bin_len; i++) {
        printf("%02X", message_bin[i]);
    }
    printf("\n");

    printf("signature_bin= ");
    for(int i = 0; i< signature_bin_len; i++) {
        printf("%02X", signature_bin[i]);
    }
    printf("\n");

    ret = sm2_sign_verify(puk_bin, puk_bin_len, message_bin, message_bin_len, signature_bin, signature_bin_len);
    printf("ret = %d\n", ret);

    //assert_int_equal(ret, 0);
}

void test_sm2_generate_keypair()
{
    char puk[144] = { 0x0 };
    char pvk[144] = { 0x0 };
    int pvk_len;
    int puk_len;

    char puk_hex[512] = { 0x0};
    char pvk_hex[512] = { 0x0};
    int pvk_hex_len = 0;
    int puk_hex_len = 0;
    
    int ret = -1;

    ret = sm2_generate_keypair(pvk, &pvk_len, puk, &puk_len);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = bin_to_hex(pvk, pvk_len, pvk_hex, &pvk_hex_len);

    ret = bin_to_hex(puk, puk_len, puk_hex, &puk_hex_len);

    printf("private key[%d]= %s\n", pvk_len, pvk_hex);
    printf("public key[%d]= %s\n", puk_len, puk_hex);
}

void test_sm2_get_puk_from_pvk()
{
    char puk[144] = { 0x0 };
    char* pvk = "74F3D6BCC82D29819BC9D9445210B3C581373715E3D728A54580B675C3CD6620";
    int pvk_len;
    int puk_len;

    char puk_hex[512] = { 0x0};
    char pvk_hex[512] = { 0x0};
    int pvk_hex_len = 0;
    int puk_hex_len = 0;

    char pvk_bin[64] = { 0x0};
    int pvk_bin_len = 0;
    char* expected_puk_hex = "0492F775BC22B55B8CCBD2B8BE78E9F64D6AA74283C3A5127F8A50DEE107456A7FE28E2A15C219408FE05147A8C968FD88D7A88179530F1D836392C00A4B484DCD";
    
    int ret = -1;

    hex_to_bin(pvk, 64, pvk_bin, &pvk_bin_len);
    
    ret = sm2_get_puk_from_pvk(pvk_bin, pvk_bin_len, puk, &puk_len);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ret = bin_to_hex(puk, puk_len, puk_hex, &puk_hex_len);

    TEST_ASSERT_EQUAL_STRING(expected_puk_hex, puk_hex);
}

int main(int argc, char* argv[]) {

    UNITY_BEGIN();

    RUN_TEST(test_sm2_compress_public_key);
    RUN_TEST(test_uncompress_public_key);
    RUN_TEST(test_sm2_sign_with_pem);
    RUN_TEST(test_sm2_sign);
    RUN_TEST(test_sm2_sign_verify);
    RUN_TEST(test_sm2_sign_verify_2);
    RUN_TEST(test_sm2_generate_keypair);
    RUN_TEST(test_sm2_get_puk_from_pvk);
    
    return UNITY_END();
}
