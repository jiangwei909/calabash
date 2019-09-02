#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include "calabash.h"
#include "unity/unity.h"

#include "test_pem.h"

void test_sm2_read_pvk_from_pemfile()
{
    char* pemfile = "cakey.pem";
    int ret = -1;
    char pvk[64] = { 0x0 };
    int pvk_len = 0;
    char pvk_hex[128] = { 0x0 };
    int pvk_hex_len = 0;
    char* expected_pvk = "74F3D6BCC82D29819BC9D9445210B3C581373715E3D728A54580B675C3CD6620";
    
    ret = sm2_read_pvk_from_pemfile(pemfile, pvk, &pvk_len);

    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_INT(32, pvk_len);
    
    bin_to_hex(pvk, pvk_len, pvk_hex, &pvk_hex_len);
    TEST_ASSERT_EQUAL_STRING(expected_pvk, pvk_hex);
}

void test_sm2_read_pvk_from_pem_str()
{
    char* pem_str = "-----BEGIN EC PARAMETERS-----\n\
BggqgRzPVQGCLQ==\n\
-----END EC PARAMETERS-----\n\
-----BEGIN EC PRIVATE KEY-----\n\
MHcCAQEEIHTz1rzILSmBm8nZRFIQs8WBNzcV49copUWAtnXDzWYgoAoGCCqBHM9V\n\
AYItoUQDQgAEkvd1vCK1W4zL0ri+eOn2TWqnQoPDpRJ/ilDe4QdFan/ijioVwhlA\n\
j+BRR6jJaP2I16iBeVMPHYNjksAKS0hNzQ==\n\
-----END EC PRIVATE KEY-----";
    int ret = -1;
    char pvk[64] = { 0x0 };
    int pvk_len = 0;
    char pvk_hex[128] = { 0x0 };
    int pvk_hex_len = 0;
    char* expected_pvk = "74F3D6BCC82D29819BC9D9445210B3C581373715E3D728A54580B675C3CD6620";
    
    ret = sm2_read_pvk_from_pem_str(pem_str, strlen(pem_str), pvk, &pvk_len);

    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_INT(32, pvk_len);
    
    bin_to_hex(pvk, pvk_len, pvk_hex, &pvk_hex_len);
    TEST_ASSERT_EQUAL_STRING(expected_pvk, pvk_hex);
}

void test_sm2_read_puk_from_pemfile()
{
    char* pemfile = "publickey.pem";
    int ret = -1;
    char pvk[64] = { 0x0 };
    int pvk_len = 0;
    char pvk_hex[128] = { 0x0 };
    int pvk_hex_len = 0;
    char* expected_pvk = "92F775BC22B55B8CCBD2B8BE78E9F64D6AA74283C3A5127F8A50DEE107456A7FE28E2A15C219408FE05147A8C968FD88D7A88179530F1D836392C00A4B484DCD";
    
    ret = sm2_read_puk_from_pemfile(pemfile, pvk, &pvk_len);

    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_INT(64, pvk_len);
    
    bin_to_hex(pvk, pvk_len, pvk_hex, &pvk_hex_len);
    TEST_ASSERT_EQUAL_STRING(expected_pvk, pvk_hex);
}

void test_sm2_read_puk_from_pem_str()
{
    char* pem_str = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEkvd1vCK1W4zL0ri+eOn2TWqnQoPD\n\
pRJ/ilDe4QdFan/ijioVwhlAj+BRR6jJaP2I16iBeVMPHYNjksAKS0hNzQ==\n\
-----END PUBLIC KEY-----";
    int ret = -1;
    char pvk[64] = { 0x0 };
    int pvk_len = 0;
    char pvk_hex[128] = { 0x0 };
    int pvk_hex_len = 0;
    char* expected_pvk = "92F775BC22B55B8CCBD2B8BE78E9F64D6AA74283C3A5127F8A50DEE107456A7FE28E2A15C219408FE05147A8C968FD88D7A88179530F1D836392C00A4B484DCD";
    
    ret = sm2_read_puk_from_pem_str(pem_str, strlen(pem_str), pvk, &pvk_len);
    
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_INT(64, pvk_len);
    
    bin_to_hex(pvk, pvk_len, pvk_hex, &pvk_hex_len);
    TEST_ASSERT_EQUAL_STRING(expected_pvk, pvk_hex);
}