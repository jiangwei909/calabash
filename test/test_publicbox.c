#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include "calabash.h"
#include "unity/unity.h"

#include "test_publicbox.h"

void test_cb_publicbox_seal()
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

    cb_hex_to_bin(pk, strlen(pk), puk_bin);
    
    ret = cb_publicbox_seal(puk_bin, plain, strlen(plain), cipher);

    //char cipher_hex[8192] = { 0x0 };
    cb_bin_to_hex(cipher, ret, cipher_hex);

    printf("cipher len=%d cipher=%s\n", ret, cipher_hex);

    TEST_ASSERT_EQUAL_INT(0x1, cipher[0]);
    TEST_ASSERT_EQUAL_INT(145, ret);
    
}

void test_cb_publicbox_seal_open()
{
    char* sk = "74F3D6BCC82D29819BC9D9445210B3C581373715E3D728A54580B675C3CD6620";
    char *cipher = "011319BC61602C5901A99454F9AAB152E78D5DCD5A014DC431C4432B5E2F68C09333C5C7BF8C6F324D118C3D0D018B4CB95E3390FC07336DC6C5B60BF2D37180E352BC9154604A3723183A19A43B62A804EA64198172BCD1F077A2A5AC717B524C0022BC9C535FD6A5A925D08FFEA2F520BFC5E8D716ACCF6A465AEC3AD8A0CA5EFD5EC52BEF77F45BD94C370270A47B3E";
    //char *cipher = "011E85A546887775FBC2A244B8573ECBA98A67034EA8D4D6A891DB20DEB285E2C9866CB5B06E29568842874B18FDA822F8F219680D2CEB1FE6190E35A4B83F995C1D2524580AD2B8CEE78D5D0811C1B64EF9F34FCFE1DC5CC9D4CB951996E72D9F56FD18E2B5D608582E17FAF9A1D3334A3F7A4CEFA11A141712E5D2DBC185D8823AB93B8C78FCEED4A544D389D8A10BBA";
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

    cb_hex_to_bin(sk, strlen(sk), pvk_bin);
    cipher_bin_len = cb_hex_to_bin(cipher, strlen(cipher), cipher_bin);
    
    plain_len = cb_publicbox_seal_open(pvk_bin, cipher_bin, cipher_bin_len, plain);
    
    TEST_ASSERT_EQUAL_INT(48, plain_len);
    TEST_ASSERT_EQUAL_STRING(expected_plain, plain);
}