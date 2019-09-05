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
#include "test_keyexchange.h"
#include "test_sm2.h"
#include "test_sm4.h"
#include "test_secretbox.h"
#include "test_kdf.h"
#include "test_pem.h"
#include "test_sm3.h"
#include "test_publicbox.h"

#define CAKEY_FILEPATH "./cakey.pem"
#define PUBLICKEY_FILEPATH "./publickey.pem"
#define RSA_PUBLICKEY_FILEPATH "./rsa_publickey.pem"

void setupdata() 
{  
    printf("Setuping data... ");

    char *cakey_data = "-----BEGIN EC PARAMETERS-----\n\
BggqgRzPVQGCLQ==\n\
-----END EC PARAMETERS-----\n\
-----BEGIN EC PRIVATE KEY-----\n\
MHcCAQEEIHTz1rzILSmBm8nZRFIQs8WBNzcV49copUWAtnXDzWYgoAoGCCqBHM9V\n\
AYItoUQDQgAEkvd1vCK1W4zL0ri+eOn2TWqnQoPDpRJ/ilDe4QdFan/ijioVwhlA\n\
j+BRR6jJaP2I16iBeVMPHYNjksAKS0hNzQ==\n\
-----END EC PRIVATE KEY-----\n";

    char *publickey_data = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEkvd1vCK1W4zL0ri+eOn2TWqnQoPD\n\
pRJ/ilDe4QdFan/ijioVwhlAj+BRR6jJaP2I16iBeVMPHYNjksAKS0hNzQ==\n\
-----END PUBLIC KEY-----\n";

    char *rsa_publickey_data = "-----BEGIN PUBLIC KEY-----\n\
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCm02/TPXXd2sw6fpeMGH/A/Ff+\n\
oTPHqjdDi+rFCYdLHGIVNtX3RtaeUnpOCktIeiLim8LMjULAr33g4IbOABZFLfkM\n\
9fRw5qqig49q1NH85KthU9hQdk5re69QN9qaGGsNJ2PP+EOBnFrp8Unb/MuzPK6X\n\
M80EAgjkaQKZyKloVQIDAQAB\n\
-----END PUBLIC KEY-----\n";

    FILE *fp = fopen(CAKEY_FILEPATH, "w+");
    fwrite(cakey_data, 1, strlen(cakey_data), fp);
    fclose(fp);

    fp = fopen(PUBLICKEY_FILEPATH, "w+");
    fwrite(publickey_data, 1, strlen(publickey_data), fp);
    fclose(fp);

    fp = fopen(RSA_PUBLICKEY_FILEPATH, "w+");
    fwrite(rsa_publickey_data, 1, strlen(rsa_publickey_data), fp);
    fclose(fp);

    printf("DONE\n");
}

void cleanup() 
{
    printf("Cleanup data...");

    remove(CAKEY_FILEPATH);
    remove(PUBLICKEY_FILEPATH);
    remove(RSA_PUBLICKEY_FILEPATH);

    printf("DONE\n");
}

void test_remove_format_from_cipher_text()
{
    char* cipher_text = "308199022060EDC5BAFEDBD1B8774A28314035D6CED587E166FCC399F3166499C7D98054A3022100C60E7506FFABBEFE21FF59AABDC9BC255B7D8F4D4A597506FEF099DC704339A504202FD12F6B82E5E81982EBD68E679E2EEE0E9294604BF147B565C8BC450F0AB5B20430D5CE6D9943D09DA2CF544565C67E867AC23A3AEA4BA51211248D745C5D32894EC0352AF6C8956EE6A640C74F30DDC20D";
    int cipher_text_len;
    char cipher_text_bin[2048] = { 0x0 };
    int cipher_text_bin_len;
    int ret = -1;
    char no_string[1024] = { 0x0 };
    int no_string_len = 0;
    char* expected_no_string = "60EDC5BAFEDBD1B8774A28314035D6CED587E166FCC399F3166499C7D98054A3C60E7506FFABBEFE21FF59AABDC9BC255B7D8F4D4A597506FEF099DC704339A52FD12F6B82E5E81982EBD68E679E2EEE0E9294604BF147B565C8BC450F0AB5B2D5CE6D9943D09DA2CF544565C67E867AC23A3AEA4BA51211248D745C5D32894EC0352AF6C8956EE6A640C74F30DDC20D";
    char no_string_hex[2096] = { 0x0 };
    int no_string_hex_len;
    
    hex_to_bin(cipher_text, strlen(cipher_text), cipher_text_bin, &cipher_text_bin_len); 
    ret = decode_cipher_text(cipher_text_bin, cipher_text_bin_len, no_string, &no_string_len);
    TEST_ASSERT_EQUAL_INT(0, ret);

    bin_to_hex(no_string, no_string_len, no_string_hex, &no_string_hex_len);
    
    TEST_ASSERT_EQUAL_STRING(expected_no_string, no_string_hex);
}

void test_encode_cipher_text()
{
    char* cipher_text = "60EDC5BAFEDBD1B8774A28314035D6CED587E166FCC399F3166499C7D98054A3C60E7506FFABBEFE21FF59AABDC9BC255B7D8F4D4A597506FEF099DC704339A52FD12F6B82E5E81982EBD68E679E2EEE0E9294604BF147B565C8BC450F0AB5B2D5CE6D9943D09DA2CF544565C67E867AC23A3AEA4BA51211248D745C5D32894EC0352AF6C8956EE6A640C74F30DDC20D";
    int cipher_text_len;
    char cipher_text_bin[2048] = { 0x0 };
    int cipher_text_bin_len;
    int ret = -1;
    char no_string[1024] = { 0x0 };
    int no_string_len = 0;
    char* expected_no_string = "308199022060EDC5BAFEDBD1B8774A28314035D6CED587E166FCC399F3166499C7D98054A3022100C60E7506FFABBEFE21FF59AABDC9BC255B7D8F4D4A597506FEF099DC704339A504202FD12F6B82E5E81982EBD68E679E2EEE0E9294604BF147B565C8BC450F0AB5B20430D5CE6D9943D09DA2CF544565C67E867AC23A3AEA4BA51211248D745C5D32894EC0352AF6C8956EE6A640C74F30DDC20D";
    char no_string_hex[2096] = { 0x0 };
    int no_string_hex_len;
    
    hex_to_bin(cipher_text, strlen(cipher_text), cipher_text_bin, &cipher_text_bin_len); 
    ret = encode_cipher_text(cipher_text_bin, cipher_text_bin_len, no_string, &no_string_len);
    TEST_ASSERT_EQUAL_INT(0, ret);

    bin_to_hex(no_string, no_string_len, no_string_hex, &no_string_hex_len);
    
    TEST_ASSERT_EQUAL_STRING(expected_no_string, no_string_hex);
}

void test_des_ecb_encrypt()
{
    char* key = "0123456789ABCDEF";
    char* key2 = "0123456789ABCDEFFEDCBA9876543210";
    char* key3 = "0123456789ABCDEFFEDCBA98765432100123456789ABCDEF";

    char* plain_hex1 = "0123456789ABCDEF";
    char* plain_hex2 = "0123456789ABCDEFFEDCBA9876543210";

    char* expected_cipher_hex1 = "56CC09E7CFDC4CEF";
    char* expected_cipher_hex2 = "1A4D672DCA6CB3351FD1B02B237AF9AE";
    char* expected_cipher_hex3 = "1A4D672DCA6CB3351FD1B02B237AF9AE";
    
    char key_bin[32] = { 0x0 };
    char plain_bin[128] = { 0x0 };
    char cipher_bin[128] = { 0x0 };
    char cipher_hex[256] = { 0x0 };
    int plain_bin_len = 0;
    char iv[16] = { 0x0 };
    int key_len = 0;
    
    hex_to_bin(key, strlen(key), key_bin, &key_len);
    hex_to_bin(plain_hex1, strlen(plain_hex1), plain_bin, &plain_bin_len);
    
    int ret = des_ecb_encrypt(key_bin, key_len, plain_bin, plain_bin_len, cipher_bin);
    
    TEST_ASSERT_EQUAL_INT(plain_bin_len, ret);
    
    bin_to_hex(cipher_bin, ret, cipher_hex, NULL);
    
    TEST_ASSERT_EQUAL_STRING(expected_cipher_hex1, cipher_hex);

    // Test DES2
    hex_to_bin(key2, strlen(key2), key_bin, &key_len);
    hex_to_bin(plain_hex2, strlen(plain_hex2), plain_bin, &plain_bin_len);
    
    ret = des_ecb_encrypt(key_bin, key_len, plain_bin, plain_bin_len, cipher_bin);
    
    TEST_ASSERT_EQUAL_INT(plain_bin_len, ret);
    
    bin_to_hex(cipher_bin, ret, cipher_hex, NULL);
    
    TEST_ASSERT_EQUAL_STRING(expected_cipher_hex2, cipher_hex);

    // Test DES3
    hex_to_bin(key3, strlen(key3), key_bin, &key_len);
    hex_to_bin(plain_hex2, strlen(plain_hex2), plain_bin, &plain_bin_len);

    TEST_ASSERT_EQUAL_INT(16, plain_bin_len);
    
    ret = des_ecb_encrypt(key_bin, key_len, plain_bin, plain_bin_len, cipher_bin);
    
    TEST_ASSERT_EQUAL_INT(plain_bin_len, ret);
    
    bin_to_hex(cipher_bin, ret, cipher_hex, NULL);
    
    TEST_ASSERT_EQUAL_STRING(expected_cipher_hex3, cipher_hex);

}

void test_des_ecb_decrypt()
{
    char* key = "0123456789ABCDEF";
    char* key2 = "0123456789ABCDEFFEDCBA9876543210";
    char* key3 = "0123456789ABCDEFFEDCBA98765432100123456789ABCDEF";

    char* expected_plain_hex1 = "0123456789ABCDEF";
    char* expected_plain_hex2 = "0123456789ABCDEFFEDCBA9876543210";

    char* cipher_hex1 = "56CC09E7CFDC4CEF";
    char* cipher_hex2 = "1A4D672DCA6CB3351FD1B02B237AF9AE";
    char* cipher_hex3 = "1A4D672DCA6CB3351FD1B02B237AF9AE";
    
    char key_bin[32] = { 0x0 };
    char plain_bin[128] = { 0x0 };
    char cipher_bin[128] = { 0x0 };
    char plain_hex[256] = { 0x0 };
    int cipher_bin_len = 0;
    int plain_bin_len = 0;
    char iv[16] = { 0x0 };
    int key_len = 0;
    
    hex_to_bin(key, strlen(key), key_bin, &key_len);
    hex_to_bin(cipher_hex1, strlen(cipher_hex1), cipher_bin, &cipher_bin_len);
    
    int ret = des_ecb_decrypt(key_bin, key_len, cipher_bin, cipher_bin_len, plain_bin);
    
    TEST_ASSERT_EQUAL_INT(cipher_bin_len, ret);
    
    bin_to_hex(plain_bin, ret, plain_hex, NULL);
    
    TEST_ASSERT_EQUAL_STRING(expected_plain_hex1, plain_hex);

    // Test DES2
    hex_to_bin(key2, strlen(key2), key_bin, &key_len);
    hex_to_bin(cipher_hex2, strlen(cipher_hex2), cipher_bin, &cipher_bin_len);
    
    ret = des_ecb_decrypt(key_bin, key_len, cipher_bin, cipher_bin_len, plain_bin);
    
    TEST_ASSERT_EQUAL_INT(cipher_bin_len, ret);
    
    bin_to_hex(plain_bin, ret, plain_hex, NULL);
    
    TEST_ASSERT_EQUAL_STRING(expected_plain_hex2, plain_hex);

    // Test DES3
    hex_to_bin(key3, strlen(key3), key_bin, &key_len);
    hex_to_bin(cipher_hex2, strlen(cipher_hex2), cipher_bin, &cipher_bin_len);

    TEST_ASSERT_EQUAL_INT(16, cipher_bin_len);
    
    ret = des_ecb_decrypt(key_bin, key_len, cipher_bin, cipher_bin_len, plain_bin);
    
    TEST_ASSERT_EQUAL_INT(cipher_bin_len, ret);
    
    bin_to_hex(plain_bin, ret, plain_hex, NULL);
    
    TEST_ASSERT_EQUAL_STRING(expected_plain_hex2, plain_hex);

}

void test_des_cbc_encrypt()
{
    char iv[8] = { 0x0 };
    char* key = "0123456789ABCDEF";
    char* key2 = "0123456789ABCDEFFEDCBA9876543210";
    char* key3 = "0123456789ABCDEFFEDCBA98765432100123456789ABCDEF";

    char* plain_hex1 = "0123456789ABCDEF";
    char* plain_hex2 = "0123456789ABCDEFFEDCBA9876543210";

    char* expected_cipher_hex1 = "56CC09E7CFDC4CEF";
    char* expected_cipher_hex2 = "1A4D672DCA6CB3354DD0077A99EB35A7";
    char* expected_cipher_hex3 = "1A4D672DCA6CB3354DD0077A99EB35A7";
    
    char key_bin[32] = { 0x0 };
    char plain_bin[128] = { 0x0 };
    char cipher_bin[128] = { 0x0 };
    char cipher_hex[256] = { 0x0 };
    int plain_bin_len = 0;

    int key_len = 0;
    
    hex_to_bin(key, strlen(key), key_bin, &key_len);
    hex_to_bin(plain_hex1, strlen(plain_hex1), plain_bin, &plain_bin_len);
    
    int ret = des_cbc_encrypt(key_bin, key_len, iv, plain_bin, plain_bin_len, cipher_bin);
    
    TEST_ASSERT_EQUAL_INT(plain_bin_len, ret);
    
    bin_to_hex(cipher_bin, ret, cipher_hex, NULL);
    
    TEST_ASSERT_EQUAL_STRING(expected_cipher_hex1, cipher_hex);

    // Test DES2
    hex_to_bin(key2, strlen(key2), key_bin, &key_len);
    hex_to_bin(plain_hex2, strlen(plain_hex2), plain_bin, &plain_bin_len);

    memset(iv, 0x0, sizeof(iv));
    ret = des_cbc_encrypt(key_bin, key_len, iv, plain_bin, plain_bin_len, cipher_bin);
    
    TEST_ASSERT_EQUAL_INT(plain_bin_len, ret);
    
    bin_to_hex(cipher_bin, ret, cipher_hex, NULL);
    
    TEST_ASSERT_EQUAL_STRING(expected_cipher_hex2, cipher_hex);

    // Test DES3
    hex_to_bin(key3, strlen(key3), key_bin, &key_len);
    hex_to_bin(plain_hex2, strlen(plain_hex2), plain_bin, &plain_bin_len);

    TEST_ASSERT_EQUAL_INT(16, plain_bin_len);

    memset(iv, 0x0, sizeof(iv));
    ret = des_cbc_encrypt(key_bin, key_len, iv, plain_bin, plain_bin_len, cipher_bin);
    
    TEST_ASSERT_EQUAL_INT(plain_bin_len, ret);
    
    bin_to_hex(cipher_bin, ret, cipher_hex, NULL);
    
    TEST_ASSERT_EQUAL_STRING(expected_cipher_hex3, cipher_hex);

}

void test_des_cbc_decrypt()
{
    char iv[8] = { 0x0 };
    char* key = "0123456789ABCDEF";
    char* key2 = "0123456789ABCDEFFEDCBA9876543210";
    char* key3 = "0123456789ABCDEFFEDCBA98765432100123456789ABCDEF";

    char* expected_plain_hex1 = "0123456789ABCDEF";
    char* expected_plain_hex2 = "0123456789ABCDEFFEDCBA9876543210";

    char* cipher_hex1 = "56CC09E7CFDC4CEF";
    char* cipher_hex2 = "1A4D672DCA6CB3354DD0077A99EB35A7";
    char* cipher_hex3 = "1A4D672DCA6CB3354DD0077A99EB35A7";
    
    char key_bin[32] = { 0x0 };
    char plain_bin[128] = { 0x0 };
    char cipher_bin[128] = { 0x0 };
    char plain_hex[256] = { 0x0 };
    int cipher_bin_len = 0;
    int plain_bin_len = 0;

    int key_len = 0;
    
    hex_to_bin(key, strlen(key), key_bin, &key_len);
    hex_to_bin(cipher_hex1, strlen(cipher_hex1), cipher_bin, &cipher_bin_len);
    
    int ret = des_cbc_decrypt(key_bin, key_len, iv, cipher_bin, cipher_bin_len, plain_bin);
    
    TEST_ASSERT_EQUAL_INT(cipher_bin_len, ret);
    
    bin_to_hex(plain_bin, ret, plain_hex, NULL);
    
    TEST_ASSERT_EQUAL_STRING(expected_plain_hex1, plain_hex);

    // Test DES2
    hex_to_bin(key2, strlen(key2), key_bin, &key_len);
    hex_to_bin(cipher_hex2, strlen(cipher_hex2), cipher_bin, &cipher_bin_len);

    memset(iv, 0x0, sizeof(iv));
    ret = des_cbc_decrypt(key_bin, key_len, iv, cipher_bin, cipher_bin_len, plain_bin);
    
    TEST_ASSERT_EQUAL_INT(cipher_bin_len, ret);
    
    bin_to_hex(plain_bin, ret, plain_hex, NULL);
    
    TEST_ASSERT_EQUAL_STRING(expected_plain_hex2, plain_hex);

    // Test DES3
    hex_to_bin(key3, strlen(key3), key_bin, &key_len);
    hex_to_bin(cipher_hex2, strlen(cipher_hex2), cipher_bin, &cipher_bin_len);

    TEST_ASSERT_EQUAL_INT(16, cipher_bin_len);

    memset(iv, 0x0, sizeof(iv));
    ret = des_cbc_decrypt(key_bin, key_len, iv, cipher_bin, cipher_bin_len, plain_bin);
    
    TEST_ASSERT_EQUAL_INT(cipher_bin_len, ret);
    
    bin_to_hex(plain_bin, ret, plain_hex, NULL);
    
    TEST_ASSERT_EQUAL_STRING(expected_plain_hex2, plain_hex);

}


void test_rsa_read_key_from_pem_file()
{
    char* pemfile = "rsa_publickey.pem";
    int ret = -1;
    char pvk[2064] = { 0x0 };
    int pvk_len = 0;
    char pvk_hex[2128] = { 0x0 };
    int pvk_hex_len = 0;
    char* expected_pvk = "30819F300D06092A864886F70D010101050003818D0030818902818100A6D36FD33D75DDDACC3A7E978C187FC0FC57FEA133C7AA37438BEAC509874B1C621536D5F746D69E527A4E0A4B487A22E29BC2CC8D42C0AF7DE0E086CE0016452DF90CF5F470E6AAA2838F6AD4D1FCE4AB6153D850764E6B7BAF5037DA9A186B0D2763CFF843819C5AE9F149DBFCCBB33CAE9733CD040208E4690299C8A968550203010001";
    
    pvk_len = rsa_read_key_from_pem_file(pemfile, pvk);

    TEST_ASSERT_EQUAL_INT(162, pvk_len);
    
    bin_to_hex(pvk, pvk_len, pvk_hex, &pvk_hex_len);
    TEST_ASSERT_EQUAL_STRING(expected_pvk, pvk_hex);
}

void test_rsa_read_key_from_pem_str()
{
    char* pem_str = "-----BEGIN PUBLIC KEY-----\n\
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCm02/TPXXd2sw6fpeMGH/A/Ff+\n\
oTPHqjdDi+rFCYdLHGIVNtX3RtaeUnpOCktIeiLim8LMjULAr33g4IbOABZFLfkM\n\
9fRw5qqig49q1NH85KthU9hQdk5re69QN9qaGGsNJ2PP+EOBnFrp8Unb/MuzPK6X\n\
M80EAgjkaQKZyKloVQIDAQAB \n\
-----END PUBLIC KEY-----";
    //  char pem_str[2048] = { 0x0 };
    
    //char* pemfile = "rsa_publickey.pem";
    int ret = -1;
    char pvk[2064] = { 0x0 };
    int pvk_len = 0;
    char pvk_hex[2128] = { 0x0 };
    int pvk_hex_len = 0;
    char* expected_pvk = "30819F300D06092A864886F70D010101050003818D0030818902818100A6D36FD33D75DDDACC3A7E978C187FC0FC57FEA133C7AA37438BEAC509874B1C621536D5F746D69E527A4E0A4B487A22E29BC2CC8D42C0AF7DE0E086CE0016452DF90CF5F470E6AAA2838F6AD4D1FCE4AB6153D850764E6B7BAF5037DA9A186B0D2763CFF843819C5AE9F149DBFCCBB33CAE9733CD040208E4690299C8A968550203010001";
/*
    FILE* fp = fopen(pemfile, "r");
    int s = fread(pem_str, 1, 1024, fp);
    fclose(fp);
*/  
    pvk_len = rsa_read_key_from_pem_str(pem_str, strlen(pem_str), pvk);

    TEST_ASSERT_EQUAL_INT(162, pvk_len);
    
    bin_to_hex(pvk, pvk_len, pvk_hex, &pvk_hex_len);
    TEST_ASSERT_EQUAL_STRING(expected_pvk, pvk_hex);
}

void test_rsa_encrypt()
{
    char* pemfile = "rsa_publickey.pem";
    int ret = -1;
    //char *pvk = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCm02/TPXXd2sw6fpeMGH/A/Ff+oTPHqjdDi+rFCYdLHGIVNtX3RtaeUnpOCktIeiLim8LMjULAr33g4IbOABZFLfkM9fRw5qqig49q1NH85KthU9hQdk5re69QN9qaGGsNJ2PP+EOBnFrp8Unb/MuzPK6XM80EAgjkaQKZyKloVQIDAQAB";
    char *pvk2 ="30819F300D06092A864886F70D010101050003818D0030818902818100A6D36FD33D75DDDACC3A7E978C187FC0FC57FEA133C7AA37438BEAC509874B1C621536D5F746D69E527A4E0A4B487A22E29BC2CC8D42C0AF7DE0E086CE0016452DF90CF5F470E6AAA2838F6AD4D1FCE4AB6153D850764E6B7BAF5037DA9A186B0D2763CFF843819C5AE9F149DBFCCBB33CAE9733CD040208E4690299C8A968550203010001";
    //char *pvk = "30818902818100A6D36FD33D75DDDACC3A7E978C187FC0FC57FEA133C7AA37438BEAC509874B1C621536D5F746D69E527A4E0A4B487A22E29BC2CC8D42C0AF7DE0E086CE0016452DF90CF5F470E6AAA2838F6AD4D1FCE4AB6153D850764E6B7BAF5037DA9A186B0D2763CFF843819C5AE9F149DBFCCBB33CAE9733CD040208E4690299C8A968550203010001";
    char *pvk = "30818902818100B91DED10AFDB87C9DD1268AF49F416CC1119173CBB67A338A14DB3C4B912945085670BF7191C2B6551C75562B83891A591D106A87933C9FDF39375D6667D68A904AB788A80871D9C1850C51AD92CAD96A2467EFB1C0AD3AC6B7BEF175EA2440B7C5C3F53DE7EB764919CF658575F841B11297CA5E12DF09212460F494D314C710203010001";
    
    int pvk_len = 0;
    char pvk_hex[2128] = { 0x0 };
    int pvk_hex_len = 0;
    char pvk_bin[256] = { 0x0 };
    int pvk_bin_len = 0;
    
    char* expected_pvk = "";
    //char* plain = "12345678";
    char* plain = "0123456789ABCDEFFEDCBA9876543210";
    char cipher[512] = { 0x0 };

    int cipher_len;

    char cipher_hex[512] = { 0x0 };
    int cipher_hex_len = 0;

	char plain_bin[32] = { 0x0 };
	int plain_bin_len = 0;
    
    hex_to_bin(pvk, strlen(pvk), pvk_bin, &pvk_bin_len);
    hex_to_bin(plain, strlen(plain), plain_bin, &plain_bin_len);
    
    cipher_len = rsa_encrypt(pvk_bin, pvk_bin_len, plain_bin, plain_bin_len, cipher);

    TEST_ASSERT_EQUAL_INT(128, cipher_len);
    
    bin_to_hex(cipher, cipher_len, cipher_hex, &cipher_hex_len);
	printf("cipher = %s\n", cipher_hex);

    memset(pvk_bin, 0x0, sizeof(pvk_bin));
    memset(cipher, 0x0, sizeof(cipher));
    
    hex_to_bin(pvk2, strlen(pvk2), pvk_bin, &pvk_bin_len);
    cipher_len = rsa_encrypt(pvk_bin, pvk_bin_len, plain, strlen(plain), cipher);

    TEST_ASSERT_EQUAL_INT(128, cipher_len);

}

void test_rsa_decrypt()
{
    int ret = -1;
    //char *pvk = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCm02/TPXXd2sw6fpeMGH/A/Ff+oTPHqjdDi+rFCYdLHGIVNtX3RtaeUnpOCktIeiLim8LMjULAr33g4IbOABZFLfkM9fRw5qqig49q1NH85KthU9hQdk5re69QN9qaGGsNJ2PP+EOBnFrp8Unb/MuzPK6XM80EAgjkaQKZyKloVQIDAQAB";
    //char *pvk ="30819F300D06092A864886F70D010101050003818D0030818902818100A6D36FD33D75DDDACC3A7E978C187FC0FC57FEA133C7AA37438BEAC509874B1C621536D5F746D69E527A4E0A4B487A22E29BC2CC8D42C0AF7DE0E086CE0016452DF90CF5F470E6AAA2838F6AD4D1FCE4AB6153D850764E6B7BAF5037DA9A186B0D2763CFF843819C5AE9F149DBFCCBB33CAE9733CD040208E4690299C8A968550203010001";
    char *pvk = "3082025D02010002818100A6D36FD33D75DDDACC3A7E978C187FC0FC57FEA133C7AA37438BEAC509874B1C621536D5F746D69E527A4E0A4B487A22E29BC2CC8D42C0AF7DE0E086CE0016452DF90CF5F470E6AAA2838F6AD4D1FCE4AB6153D850764E6B7BAF5037DA9A186B0D2763CFF843819C5AE9F149DBFCCBB33CAE9733CD040208E4690299C8A968550203010001028180576C6625A507A7838992FDD41D2E998460B91C4F0DFB8C4FF9ADD11200B44DC04A0623FE6CDF4A891D5FCA95CA6DE8D36F3D811000D70272F4DC6BCD39170293D41060E3B7B8513068B76FFCBA3D012DD38E234BA10C1D9A0FCADA6614C7AA8B3146397A5496F04C700F794371023BE90EC5B285157E5E2DEF2EDEB37F803201024100E9A7A233B21EBB36613EF06702D386FA439D423FD60D0F956BEDD0C9BE640B82EFF5DBB5DCF12C56731A534014B36143AFE3B2FA787AD20218F3F8DFE6DADDC5024100B6C7B09DF04C055808EAC023A5ACAE021A8351266DF32F2AA39B41E20A752564E5304244D14F1397D64F478CD523834719793EE746CB78910A9255431BCD195102410095E937E8731FC47DDF66C2575538E2212FC07600FF14E22ABC5498E0D786D8DBE999949DDA63E24E950B0EDECE6948BE64DB72B9C1130C2ACC57BC15EBC801010240452A8BCB38838C02245DB117CC39EC1F1FA951AC192F4D49F55F6B2EFE861600783A2AD99FDB2CAEE88A57A9137EBCCECAF4F6B8CE31710E71D1AE3216F32601024100E74E2809E8A779332857C5F4B5B2056D49C9B0C774CDB65CA6224AF9CBD79413A3802E68FB878E46EEA7996FD29B9B97193D44A08A618755628E4C1A5BF12181";
    
    int pvk_len = 0;
    char pvk_hex[2128] = { 0x0 };
    int pvk_hex_len = 0;
    char pvk_bin[1024] = { 0x0 };
    int pvk_bin_len = 0;

    char* expected_plain = "12345678";
    char *cipher_hex = "927FBB727477A5BCF425C1287899ED9BA4237059FA3255A97D09D2E2B2E3D9D79F3B09345060C8169CB458F6F5DA4CF13E75CFA2C7F13684EFE67EEC8BE8A1D8CB71A3AFA69F762F259654B79CC5E1A0C1EFB51DBE6D2009BD46E7D7F33FDD60162E3F252203F790D6A326D5580341B9F27970F799E8437F0F96CE4F4C0FED61";
    char plain[64] =  { 0x0 };
    int plain_len = 0;
    
    int cipher_hex_len;

    char cipher_bin[512] = { 0x0 };
    int cipher_bin_len = 0;
    
    hex_to_bin(pvk, strlen(pvk), pvk_bin, &pvk_bin_len);
    hex_to_bin(cipher_hex, strlen(cipher_hex), cipher_bin, &cipher_bin_len);
    
    plain_len = rsa_decrypt(pvk_bin, pvk_bin_len, cipher_bin, cipher_bin_len, plain);

    TEST_ASSERT_EQUAL_INT(8, plain_len);
    TEST_ASSERT_EQUAL_STRING(expected_plain, plain);
}

void test_rsa_sign()
{
    int ret = -1;
    char *pvk = "3082025D02010002818100A6D36FD33D75DDDACC3A7E978C187FC0FC57FEA133C7AA37438BEAC509874B1C621536D5F746D69E527A4E0A4B487A22E29BC2CC8D42C0AF7DE0E086CE0016452DF90CF5F470E6AAA2838F6AD4D1FCE4AB6153D850764E6B7BAF5037DA9A186B0D2763CFF843819C5AE9F149DBFCCBB33CAE9733CD040208E4690299C8A968550203010001028180576C6625A507A7838992FDD41D2E998460B91C4F0DFB8C4FF9ADD11200B44DC04A0623FE6CDF4A891D5FCA95CA6DE8D36F3D811000D70272F4DC6BCD39170293D41060E3B7B8513068B76FFCBA3D012DD38E234BA10C1D9A0FCADA6614C7AA8B3146397A5496F04C700F794371023BE90EC5B285157E5E2DEF2EDEB37F803201024100E9A7A233B21EBB36613EF06702D386FA439D423FD60D0F956BEDD0C9BE640B82EFF5DBB5DCF12C56731A534014B36143AFE3B2FA787AD20218F3F8DFE6DADDC5024100B6C7B09DF04C055808EAC023A5ACAE021A8351266DF32F2AA39B41E20A752564E5304244D14F1397D64F478CD523834719793EE746CB78910A9255431BCD195102410095E937E8731FC47DDF66C2575538E2212FC07600FF14E22ABC5498E0D786D8DBE999949DDA63E24E950B0EDECE6948BE64DB72B9C1130C2ACC57BC15EBC801010240452A8BCB38838C02245DB117CC39EC1F1FA951AC192F4D49F55F6B2EFE861600783A2AD99FDB2CAEE88A57A9137EBCCECAF4F6B8CE31710E71D1AE3216F32601024100E74E2809E8A779332857C5F4B5B2056D49C9B0C774CDB65CA6224AF9CBD79413A3802E68FB878E46EEA7996FD29B9B97193D44A08A618755628E4C1A5BF12181";
    
    int pvk_len = 0;
    char pvk_hex[2128] = { 0x0 };
    int pvk_hex_len = 0;
    char pvk_bin[1024] = { 0x0 };
    int pvk_bin_len = 0;

    char *msg = "helloworld";
    int digest_algo = DIGEST_MD5;

    char* expected_plain = "81E1822DE2CEBBE641E2E94BFABFAE9BF0858A4911FEBE4C0EA75E67989C709A6495110A8C34246DE22B79B7C5C921E2E630B40DB700D0226A0649E73CF5492164DF575E5FD21C1A592F19E31832AF3E7F7251D2AD33B7B207E2B21923D8C73846F138F850BD4729CA387F6FC9CF44E056A098E05CFF3403D5CAE7A08C86BE1B";
    char cipher_hex[1024] = { 0x0 };
    char plain[256] =  { 0x0 };
    int plain_len = 0;
    
    int cipher_hex_len;

    char cipher_bin[512] = { 0x0 };
    int cipher_bin_len = 0;
    
    hex_to_bin(pvk, strlen(pvk), pvk_bin, &pvk_bin_len);
    hex_to_bin(cipher_hex, strlen(cipher_hex), cipher_bin, &cipher_bin_len);
    
    plain_len = rsa_sign(pvk_bin, pvk_bin_len, msg, strlen(msg), DIGEST_MD5, plain);

    TEST_ASSERT_EQUAL_INT(128, plain_len);

    bin_to_hex(plain, plain_len, cipher_hex, &cipher_hex_len);
    TEST_ASSERT_EQUAL_STRING(expected_plain, cipher_hex);
}

void test_rsa_verify()
{
    int ret = -1;
    char *pvk = "30818902818100A6D36FD33D75DDDACC3A7E978C187FC0FC57FEA133C7AA37438BEAC509874B1C621536D5F746D69E527A4E0A4B487A22E29BC2CC8D42C0AF7DE0E086CE0016452DF90CF5F470E6AAA2838F6AD4D1FCE4AB6153D850764E6B7BAF5037DA9A186B0D2763CFF843819C5AE9F149DBFCCBB33CAE9733CD040208E4690299C8A968550203010001";
    // char *pvk = "30818902818100CB1A366991E785DAAC7261014EA5A032A6D9860C4018FD4DEAD4E436DA598B1DB6F415A6E8AA7CCBE3D7B93E99FF7F93C4D63D0DDC2BB7CD1A31ECD1035609A21814415B1500CD40B682102B3F05FD17E3D7B62B73E21CB625569893A29D5247F7BD27D1A33434D42BA3616EA05CF5E71C780A49985A02CB945AC8BE3B26715F0203010001";
    
    int pvk_len = 0;
    char pvk_hex[2128] = { 0x0 };
    int pvk_hex_len = 0;
    char pvk_bin[1024] = { 0x0 };
    int pvk_bin_len = 0;

    char *msg = "helloworld";
    int digest_algo = DIGEST_MD5;

    char* signature = "81E1822DE2CEBBE641E2E94BFABFAE9BF0858A4911FEBE4C0EA75E67989C709A6495110A8C34246DE22B79B7C5C921E2E630B40DB700D0226A0649E73CF5492164DF575E5FD21C1A592F19E31832AF3E7F7251D2AD33B7B207E2B21923D8C73846F138F850BD4729CA387F6FC9CF44E056A098E05CFF3403D5CAE7A08C86BE1B";
    char cipher_hex[1024] = { 0x0 };
    char plain[256] =  { 0x0 };
    int plain_len = 0;
    
    int cipher_hex_len;

    char cipher_bin[512] = { 0x0 };
    int cipher_bin_len = 0;
    
    hex_to_bin(pvk, strlen(pvk), pvk_bin, &pvk_bin_len);
    hex_to_bin(cipher_hex, strlen(cipher_hex), cipher_bin, &cipher_bin_len);
    hex_to_bin(signature, 256, plain, &plain_len);
    
    ret = rsa_verify(pvk_bin, pvk_bin_len, msg, strlen(msg), digest_algo, plain, plain_len);

    TEST_ASSERT_EQUAL_INT(0, ret);
}

void test_bas64_to_bin()
{
    char* pem_str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCm02/TPXXd2sw6fpeMGH/A/Ff+oTPHqjdDi+rFCYdLHGIVNtX3RtaeUnpOCktIeiLim8LMjULAr33g4IbOABZFLfkM9fRw5qqig49q1NH85KthU9hQdk5re69QN9qaGGsNJ2PP+EOBnFrp8Unb/MuzPK6XM80EAgjkaQKZyKloVQIDAQAB";

    int ret = -1;
    char pvk[2064] = { 0x0 };
    int pvk_len = 0;
    char pvk_hex[2128] = { 0x0 };
    int pvk_hex_len = 0;
    char* expected_pvk = "30819F300D06092A864886F70D010101050003818D0030818902818100A6D36FD33D75DDDACC3A7E978C187FC0FC57FEA133C7AA37438BEAC509874B1C621536D5F746D69E527A4E0A4B487A22E29BC2CC8D42C0AF7DE0E086CE0016452DF90CF5F470E6AAA2838F6AD4D1FCE4AB6153D850764E6B7BAF5037DA9A186B0D2763CFF843819C5AE9F149DBFCCBB33CAE9733CD040208E4690299C8A968550203010001";
/*
    FILE* fp = fopen(pemfile, "r");
    int s = fread(pem_str, 1, 1024, fp);
    fclose(fp);
*/  
    pvk_len = base64_to_bin(pem_str, strlen(pem_str), pvk);

    TEST_ASSERT_EQUAL_INT(162, pvk_len);
    
    bin_to_hex(pvk, pvk_len, pvk_hex, &pvk_hex_len);
    TEST_ASSERT_EQUAL_STRING(expected_pvk, pvk_hex);

    char* pem_str2 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCm02/TPXXd2sw6fpeMGH/A/Ff+\n\
oTPHqjdDi+rFCYdLHGIVNtX3RtaeUnpOCktIeiLim8LMjULAr33g4IbOABZFLfkM\n\
9fRw5qqig49q1NH85KthU9hQdk5re69QN9qaGGsNJ2PP+EOBnFrp8Unb/MuzPK6X\n\
M80EAgjkaQKZyKloVQIDAQAB\n";

    pvk_len = base64_to_bin(pem_str2, strlen(pem_str2), pvk);

    TEST_ASSERT_EQUAL_INT(162, pvk_len);
    
    bin_to_hex(pvk, pvk_len, pvk_hex, &pvk_hex_len);
    TEST_ASSERT_EQUAL_STRING(expected_pvk, pvk_hex);

}

void test_bin_to_bas64()
{
    char* expected_pvk = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCm02/TPXXd2sw6fpeMGH/A/Ff+oTPHqjdDi+rFCYdLHGIVNtX3RtaeUnpOCktIeiLim8LMjULAr33g4IbOABZFLfkM9fRw5qqig49q1NH85KthU9hQdk5re69QN9qaGGsNJ2PP+EOBnFrp8Unb/MuzPK6XM80EAgjkaQKZyKloVQIDAQAB";

    int ret = -1;
    char pvk[2064] = { 0x0 };
    int pvk_len = 0;
    char pvk_hex[2128] = { 0x0 };
    int pvk_hex_len = 0;
    char* pem_str = "30819F300D06092A864886F70D010101050003818D0030818902818100A6D36FD33D75DDDACC3A7E978C187FC0FC57FEA133C7AA37438BEAC509874B1C621536D5F746D69E527A4E0A4B487A22E29BC2CC8D42C0AF7DE0E086CE0016452DF90CF5F470E6AAA2838F6AD4D1FCE4AB6153D850764E6B7BAF5037DA9A186B0D2763CFF843819C5AE9F149DBFCCBB33CAE9733CD040208E4690299C8A968550203010001";

    char pem_bin[1024] = { 0x0 };
    int pem_bin_len = 0;
    
    hex_to_bin(pem_str, strlen(pem_str), pem_bin, &pem_bin_len);
    
    pvk_len = bin_to_base64(pem_bin, pem_bin_len, 0, pvk);
    
    //TEST_ASSERT_EQUAL_INT(216, pvk_len);

    TEST_ASSERT_EQUAL_STRING(expected_pvk, pvk);
}

void test_rsa_generate_key()
{
    char pvk[2048] = { 0x0 };
    int pvk_len = 0;
    char puk[2048] = { 0x0 };
    int puk_len = 0;

    char pvk_hex[4096] = { 0x0 };
    int pvk_hex_len = 0;
    char puk_hex[4096] = { 0x0 };
    int puk_hex_len = 0;
    
    int ret = rsa_generate_key(1024, pvk, &pvk_len, puk, &puk_len);

    TEST_ASSERT_EQUAL_INT(0, ret);
    
    bin_to_hex(pvk, pvk_len, pvk_hex, &pvk_hex_len);
    bin_to_hex(puk, puk_len, puk_hex, &puk_hex_len);
    
    printf("pvk= %s\npuk= %s\n", pvk_hex, puk_hex);
}

void test_rsa_dump_puk_to_pem_str()
{
    char* puk_hex = "30818902818100B378DC5DAE48CB55729F64095054F4F906C520BFC7F5EAAE0D50EE15CBA83B844CDBA02DA71B0D51CADD4466968BAAA9E4CF27C258E0DF8850F0D062385C1A67C2268281326D71200137631F3C031D56C69077BB3F03F2F677A32A0523A4A143B08C9BC1AE581721CC5735FFD416A1AC1E78A7B1D067B007DACCCEB96427CD2B0203010001";

    char puk[256] = { 0x0 };
    int puk_len;
    char str[1024] =  { 0x0 };

    char* expected_puk = "-----BEGIN RSA PUBLIC KEY-----\n\
MIGJAoGBALN43F2uSMtVcp9kCVBU9PkGxSC/x/Xqrg1Q7hXLqDuETNugLacbDVHK\n\
3URmlouqqeTPJ8JY4N+IUPDQYjhcGmfCJoKBMm1xIAE3Yx88Ax1WxpB3uz8D8vZ3\n\
oyoFI6ShQ7CMm8GuWBchzFc1/9QWoaweeKex0GewB9rMzrlkJ80rAgMBAAE=\n\
-----END RSA PUBLIC KEY-----\n";
    
    hex_to_bin(puk_hex, strlen(puk_hex), puk, &puk_len);
    
    int ret = rsa_dump_puk_to_pem_str(puk, puk_len, str);

    TEST_ASSERT_NOT_EQUAL(-1, ret);
    TEST_ASSERT_EQUAL_STRING(expected_puk, str);
}

void test_rsa_dump_puk_to_pkcs8_pem_str()
{
    char* puk_hex = "30818902818100B378DC5DAE48CB55729F64095054F4F906C520BFC7F5EAAE0D50EE15CBA83B844CDBA02DA71B0D51CADD4466968BAAA9E4CF27C258E0DF8850F0D062385C1A67C2268281326D71200137631F3C031D56C69077BB3F03F2F677A32A0523A4A143B08C9BC1AE581721CC5735FFD416A1AC1E78A7B1D067B007DACCCEB96427CD2B0203010001";

    char puk[256] = { 0x0 };
    int puk_len;
    char str[1024] =  { 0x0 };

    char* expected_puk = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCzeNxdrkjLVXKfZAlQVPT5BsUg\nv8f16q4NUO4Vy6g7hEzboC2nGw1Ryt1EZpaLqqnkzyfCWODfiFDw0GI4XBpnwiaC\ngTJtcSABN2MfPAMdVsaQd7s/A/L2d6MqBSOkoUOwjJvBrlgXIcxXNf/UFqGsHnin\nsdBnsAfazM65ZCfNKwIDAQAB\n-----END PUBLIC KEY-----\n";
    
    hex_to_bin(puk_hex, strlen(puk_hex), puk, &puk_len);
    
    int ret = rsa_dump_puk_to_pkcs8_pem_str(puk, puk_len, str);

    TEST_ASSERT_NOT_EQUAL(-1, ret);
    TEST_ASSERT_EQUAL_STRING(expected_puk, str);
}

void test_rsa_dump_pvk_to_pem_str()
{
    char* pvk_hex = "3082025B02010002818100CF33180C27C33738D14CA56122C4906FE3F7AD4071C929AD584646580B6CDF6408456DB774126CA54C47C611E0EA2E13BB157DA887880965B47A8418E0B248601BACEABCEA8C12E2D59F65483E5E48356835F9C68331B90DB80BDA6C62705C7D3075DD0D59FC9CA4A7609BA53845B42A789B28D762D2E42D4BAEE0928320935502030100010281807B373A3CB844AA093AC626AEEE1B107DC986975BF48E991F419880EA88D8D4BBCB0366ACAAF4EDF11ABCAFF81FD583532E752845D95B37A368C156DEE8787CFAC06E3B947934FCFF4C2417397B6FCE55345D34ADB9586255E7AC230B4D6A3EBF64B72126B7C0132D350725D23DF317341F29D55BCC60374054D90F4504A8F2FD024100E67B8AEE106B21395CE938FD56CBDBE1F1296CDCFF74C78CE3D2C615BA98F920DC4EA587811B84BF79221AEA9296E2340BC91D349DD8EEB18D40615F73FEE6FF024100E623A6FB347A39473271B7FDAA8205D27A7B52E9549D2589C683903000AF716EDE759191204EE1DA64C14ACFA10457CDD412CA09813F38A18F16BB7C6B12B9AB024014472E53FFB1CD3C84C6283371DD81BD0140C9C92FD8906DFEE55E742EF4A286979B7BC8CE3D2392CD0F891AB646FC23E41D8FAA3F71049F2E74499CE251BCF502403542A4FF57EABD5CC3C8DB9AE21E0B38E5CDAAA78344870E7699B601D5F6C45AB333244820E10095E9616E6DD4C6CB874000452FA3F0BCAB6F1104BCCB8EDED702406E3ED705B0E7F86EF9A1B7D86B08E4803B0950D0FA3C54FD71D609F1E4F854B5DC86962A1379FCC2EB7E9B8B00E678EF87F57ABCA9EEF3F112955D00C55C6DB8";

    char pvk[1024] = { 0x0 };
    int pvk_len;
    char str[4096] =  { 0x0 };

    char* expected_pvk = "-----BEGIN RSA PRIVATE KEY-----\n\
MIICWwIBAAKBgQDPMxgMJ8M3ONFMpWEixJBv4/etQHHJKa1YRkZYC2zfZAhFbbd0\n\
EmylTEfGEeDqLhO7FX2oh4gJZbR6hBjgskhgG6zqvOqMEuLVn2VIPl5INWg1+caD\n\
MbkNuAvabGJwXH0wdd0NWfycpKdgm6U4RbQqeJso12LS5C1LruCSgyCTVQIDAQAB\n\
AoGAezc6PLhEqgk6xiau7hsQfcmGl1v0jpkfQZiA6ojY1LvLA2asqvTt8Rq8r/gf\n\
1YNTLnUoRdlbN6NowVbe6Hh8+sBuO5R5NPz/TCQXOXtvzlU0XTStuVhiVeesIwtN\n\
aj6/ZLchJrfAEy01ByXSPfMXNB8p1VvMYDdAVNkPRQSo8v0CQQDme4ruEGshOVzp\n\
OP1Wy9vh8Sls3P90x4zj0sYVupj5INxOpYeBG4S/eSIa6pKW4jQLyR00ndjusY1A\n\
YV9z/ub/AkEA5iOm+zR6OUcycbf9qoIF0np7UulUnSWJxoOQMACvcW7edZGRIE7h\n\
2mTBSs+hBFfN1BLKCYE/OKGPFrt8axK5qwJAFEcuU/+xzTyExigzcd2BvQFAyckv\n\
2JBt/uVedC70ooaXm3vIzj0jks0PiRq2Rvwj5B2Pqj9xBJ8udEmc4lG89QJANUKk\n\
/1fqvVzDyNua4h4LOOXNqqeDRIcOdpm2AdX2xFqzMyRIIOEAlelhbm3UxsuHQABF\n\
L6PwvKtvEQS8y47e1wJAbj7XBbDn+G75obfYawjkgDsJUND6PFT9cdYJ8eT4VLXc\n\
hpYqE3n8wut+m4sA5njvh/V6vKnu8/ESlV0AxVxtuA==\n\
-----END RSA PRIVATE KEY-----\n";
    
    hex_to_bin(pvk_hex, strlen(pvk_hex), pvk, &pvk_len);

    int ret = rsa_dump_pvk_to_pem_str(pvk, pvk_len, str);
    
    TEST_ASSERT_NOT_EQUAL(-1, ret);
    TEST_ASSERT_EQUAL_STRING(expected_pvk, str);
}

void test_rsa_dump_pvk_to_pkcs8_pem_str()
{
    char* pvk_hex = "3082025B02010002818100CF33180C27C33738D14CA56122C4906FE3F7AD4071C929AD584646580B6CDF6408456DB774126CA54C47C611E0EA2E13BB157DA887880965B47A8418E0B248601BACEABCEA8C12E2D59F65483E5E48356835F9C68331B90DB80BDA6C62705C7D3075DD0D59FC9CA4A7609BA53845B42A789B28D762D2E42D4BAEE0928320935502030100010281807B373A3CB844AA093AC626AEEE1B107DC986975BF48E991F419880EA88D8D4BBCB0366ACAAF4EDF11ABCAFF81FD583532E752845D95B37A368C156DEE8787CFAC06E3B947934FCFF4C2417397B6FCE55345D34ADB9586255E7AC230B4D6A3EBF64B72126B7C0132D350725D23DF317341F29D55BCC60374054D90F4504A8F2FD024100E67B8AEE106B21395CE938FD56CBDBE1F1296CDCFF74C78CE3D2C615BA98F920DC4EA587811B84BF79221AEA9296E2340BC91D349DD8EEB18D40615F73FEE6FF024100E623A6FB347A39473271B7FDAA8205D27A7B52E9549D2589C683903000AF716EDE759191204EE1DA64C14ACFA10457CDD412CA09813F38A18F16BB7C6B12B9AB024014472E53FFB1CD3C84C6283371DD81BD0140C9C92FD8906DFEE55E742EF4A286979B7BC8CE3D2392CD0F891AB646FC23E41D8FAA3F71049F2E74499CE251BCF502403542A4FF57EABD5CC3C8DB9AE21E0B38E5CDAAA78344870E7699B601D5F6C45AB333244820E10095E9616E6DD4C6CB874000452FA3F0BCAB6F1104BCCB8EDED702406E3ED705B0E7F86EF9A1B7D86B08E4803B0950D0FA3C54FD71D609F1E4F854B5DC86962A1379FCC2EB7E9B8B00E678EF87F57ABCA9EEF3F112955D00C55C6DB8";

    char pvk[1024] = { 0x0 };
    int pvk_len;
    char str[4096] =  { 0x0 };

    char* expected_pvk = "-----BEGIN PRIVATE KEY-----\nMIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAM8zGAwnwzc40Uyl\nYSLEkG/j961AcckprVhGRlgLbN9kCEVtt3QSbKVMR8YR4OouE7sVfaiHiAlltHqE\nGOCySGAbrOq86owS4tWfZUg+Xkg1aDX5xoMxuQ24C9psYnBcfTB13Q1Z/Jykp2Cb\npThFtCp4myjXYtLkLUuu4JKDIJNVAgMBAAECgYB7Nzo8uESqCTrGJq7uGxB9yYaX\nW/SOmR9BmIDqiNjUu8sDZqyq9O3xGryv+B/Vg1MudShF2Vs3o2jBVt7oeHz6wG47\nlHk0/P9MJBc5e2/OVTRdNK25WGJV56wjC01qPr9ktyEmt8ATLTUHJdI98xc0HynV\nW8xgN0BU2Q9FBKjy/QJBAOZ7iu4QayE5XOk4/VbL2+HxKWzc/3THjOPSxhW6mPkg\n3E6lh4EbhL95IhrqkpbiNAvJHTSd2O6xjUBhX3P+5v8CQQDmI6b7NHo5RzJxt/2q\nggXSentS6VSdJYnGg5AwAK9xbt51kZEgTuHaZMFKz6EEV83UEsoJgT84oY8Wu3xr\nErmrAkAURy5T/7HNPITGKDNx3YG9AUDJyS/YkG3+5V50LvSihpebe8jOPSOSzQ+J\nGrZG/CPkHY+qP3EEny50SZziUbz1AkA1QqT/V+q9XMPI25riHgs45c2qp4NEhw52\nmbYB1fbEWrMzJEgg4QCV6WFubdTGy4dAAEUvo/C8q28RBLzLjt7XAkBuPtcFsOf4\nbvmht9hrCOSAOwlQ0Po8VP1x1gnx5PhUtdyGlioTefzC636biwDmeO+H9Xq8qe7z\n8RKVXQDFXG24\n-----END PRIVATE KEY-----\n";
    
    hex_to_bin(pvk_hex, strlen(pvk_hex), pvk, &pvk_len);

    int ret = rsa_dump_pvk_to_pkcs8_pem_str(pvk, pvk_len, NULL, str);
    
    TEST_ASSERT_NOT_EQUAL(-1, ret);
    TEST_ASSERT_EQUAL_STRING(expected_pvk, str);
}

void test_rsa_dump_pvk_to_pkcs8_pem_str_with_password()
{
    char* pvk_hex = "3082025B02010002818100CF33180C27C33738D14CA56122C4906FE3F7AD4071C929AD584646580B6CDF6408456DB774126CA54C47C611E0EA2E13BB157DA887880965B47A8418E0B248601BACEABCEA8C12E2D59F65483E5E48356835F9C68331B90DB80BDA6C62705C7D3075DD0D59FC9CA4A7609BA53845B42A789B28D762D2E42D4BAEE0928320935502030100010281807B373A3CB844AA093AC626AEEE1B107DC986975BF48E991F419880EA88D8D4BBCB0366ACAAF4EDF11ABCAFF81FD583532E752845D95B37A368C156DEE8787CFAC06E3B947934FCFF4C2417397B6FCE55345D34ADB9586255E7AC230B4D6A3EBF64B72126B7C0132D350725D23DF317341F29D55BCC60374054D90F4504A8F2FD024100E67B8AEE106B21395CE938FD56CBDBE1F1296CDCFF74C78CE3D2C615BA98F920DC4EA587811B84BF79221AEA9296E2340BC91D349DD8EEB18D40615F73FEE6FF024100E623A6FB347A39473271B7FDAA8205D27A7B52E9549D2589C683903000AF716EDE759191204EE1DA64C14ACFA10457CDD412CA09813F38A18F16BB7C6B12B9AB024014472E53FFB1CD3C84C6283371DD81BD0140C9C92FD8906DFEE55E742EF4A286979B7BC8CE3D2392CD0F891AB646FC23E41D8FAA3F71049F2E74499CE251BCF502403542A4FF57EABD5CC3C8DB9AE21E0B38E5CDAAA78344870E7699B601D5F6C45AB333244820E10095E9616E6DD4C6CB874000452FA3F0BCAB6F1104BCCB8EDED702406E3ED705B0E7F86EF9A1B7D86B08E4803B0950D0FA3C54FD71D609F1E4F854B5DC86962A1379FCC2EB7E9B8B00E678EF87F57ABCA9EEF3F112955D00C55C6DB8";

    char pvk[1024] = { 0x0 };
    int pvk_len;
    char str[4096] =  { 0x0 };

    char* expected_pvk = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIC1DBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQI1hgG+7qZxr0CAggA\nMAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECD0jlGsgzEHCBIICgAOke8vnrmum\nNECV7l7HzU1zR4AOdGZjJ7QhkmgHU0cHL0Rd5l8xa6O9KIs2A7WVcYoCwoNJ31c8\nDn0x7/wZDipRh7+kSsnfv1dJHts01RfKWpiJZ7DAVtF+PJ8tMSDIgkkbaIqnXdI1\nA6XiDxowKABWAdBnyJ67hTU/HUgEGV2yrLFgn9YpX6aJDA/sD7XbwPpUUPugnBhF\nD5TK5nSJr3d4gC8/ddjG4BhdGHL/mwf542xUIiFS6Bml7VvNEiJvt+tJdFuNDebk\nItr1lu6lfbFFHQZ1UpmWXXNcXuGjPfaspcLdcufcljFJ3ohIHkr1c9qMhO4N+JLX\nmDOI+Y/JBumNpxBtstP1MOBYtcU35TzumyAs8yjiem+HW9oAUOcFnOmW8hmaVZ80\nJ2nzZNJIiHYDhMwir4iljbfHdOom9knoP+wHfPhKzVxn49EyORKffC2ZP13MCVtE\nLHES4HT2gw6IQ4iV+yi7GCIlksRxIDbyFtZ9Js5pa1MIoOy4/tkPUGs+ZBIS+Jou\nyd2I9R+imelHK7vsqPi3tpl1lVy9UZpNb/D+xC0YcJIgix2oCc8G0ZVHLE1dTnl5\n5zm/JOfFo4F98qsRWnvtoewk3/8W204szPO8wR6/2pTl7OUk8pbGUrMu1HBHRGhs\nhNXPL0x8OaZx42Nf+C+0FtIDaNFNLvE8Gr7ZbkantSh5txLQUwOrkEzENlBEZuIH\nfdVFetelnSlF2pXJx3C2wXSJKiRwDjgIATS9Vd4c0fuo0jIwmAgaNWgnAvu9nLiy\nPmza/WjJhXXOnNod1iePBEcpYEU5RlN3LIGjzzm3lvI8cZrZ1SiGlaTh+chjcB9n\nqTSOcZY08og=\n-----END ENCRYPTED PRIVATE KEY-----\n";
    
    hex_to_bin(pvk_hex, strlen(pvk_hex), pvk, &pvk_len);

    int ret = rsa_dump_pvk_to_pkcs8_pem_str(pvk, pvk_len, "123456", str);
    
    TEST_ASSERT_NOT_EQUAL(-1, ret);
    //TEST_ASSERT_EQUAL_STRING(expected_pvk, str);
}


void test_rsa_dump_puk_to_pem_file()
{
    char* puk_hex = "30818902818100B378DC5DAE48CB55729F64095054F4F906C520BFC7F5EAAE0D50EE15CBA83B844CDBA02DA71B0D51CADD4466968BAAA9E4CF27C258E0DF8850F0D062385C1A67C2268281326D71200137631F3C031D56C69077BB3F03F2F677A32A0523A4A143B08C9BC1AE581721CC5735FFD416A1AC1E78A7B1D067B007DACCCEB96427CD2B0203010001";

    char puk[256] = { 0x0 };
    int puk_len;
    char *file_name = "_t_puk.pem";
    char buff[1024] = { 0x0 };
    
    char* expected_puk = "-----BEGIN RSA PUBLIC KEY-----\n\
MIGJAoGBALN43F2uSMtVcp9kCVBU9PkGxSC/x/Xqrg1Q7hXLqDuETNugLacbDVHK\n\
3URmlouqqeTPJ8JY4N+IUPDQYjhcGmfCJoKBMm1xIAE3Yx88Ax1WxpB3uz8D8vZ3\n\
oyoFI6ShQ7CMm8GuWBchzFc1/9QWoaweeKex0GewB9rMzrlkJ80rAgMBAAE=\n\
-----END RSA PUBLIC KEY-----\n";
        
    hex_to_bin(puk_hex, strlen(puk_hex), puk, &puk_len);
    
    int ret = rsa_dump_puk_to_pem_file(puk, puk_len, file_name);

    TEST_ASSERT_NOT_EQUAL(-1, ret);

    FILE* fp = fopen(file_name, "r");
    if (fp == NULL) TEST_ASSERT_EQUAL(0, -1);

    int r = fread(buff, 1, 1024, fp);
    fclose(fp);

    TEST_ASSERT_EQUAL_STRING(expected_puk, buff);
    remove(file_name);
}

void test_rsa_dump_puk_to_pkcs8_pem_file()
{
    char* puk_hex = "30818902818100B378DC5DAE48CB55729F64095054F4F906C520BFC7F5EAAE0D50EE15CBA83B844CDBA02DA71B0D51CADD4466968BAAA9E4CF27C258E0DF8850F0D062385C1A67C2268281326D71200137631F3C031D56C69077BB3F03F2F677A32A0523A4A143B08C9BC1AE581721CC5735FFD416A1AC1E78A7B1D067B007DACCCEB96427CD2B0203010001";

    char puk[256] = { 0x0 };
    int puk_len;
    char *file_name = "_t_pcks8_puk.pem";
    char buff[1024] = { 0x0 };
    
    char* expected_puk = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCzeNxdrkjLVXKfZAlQVPT5BsUg\nv8f16q4NUO4Vy6g7hEzboC2nGw1Ryt1EZpaLqqnkzyfCWODfiFDw0GI4XBpnwiaC\ngTJtcSABN2MfPAMdVsaQd7s/A/L2d6MqBSOkoUOwjJvBrlgXIcxXNf/UFqGsHnin\nsdBnsAfazM65ZCfNKwIDAQAB\n-----END PUBLIC KEY-----\n";    

    hex_to_bin(puk_hex, strlen(puk_hex), puk, &puk_len);
    
    int ret = rsa_dump_puk_to_pkcs8_pem_file(puk, puk_len, file_name);

    TEST_ASSERT_NOT_EQUAL(-1, ret);

    FILE* fp = fopen(file_name, "r");
    if (fp == NULL) TEST_ASSERT_EQUAL(0, -1);

    int r = fread(buff, 1, 1024, fp);
    fclose(fp);

    TEST_ASSERT_EQUAL_STRING(expected_puk, buff);
    remove(file_name);
}

void test_rsa_dump_pvk_to_pem_file()
{
    char* pvk_hex = "3082025B02010002818100CF33180C27C33738D14CA56122C4906FE3F7AD4071C929AD584646580B6CDF6408456DB774126CA54C47C611E0EA2E13BB157DA887880965B47A8418E0B248601BACEABCEA8C12E2D59F65483E5E48356835F9C68331B90DB80BDA6C62705C7D3075DD0D59FC9CA4A7609BA53845B42A789B28D762D2E42D4BAEE0928320935502030100010281807B373A3CB844AA093AC626AEEE1B107DC986975BF48E991F419880EA88D8D4BBCB0366ACAAF4EDF11ABCAFF81FD583532E752845D95B37A368C156DEE8787CFAC06E3B947934FCFF4C2417397B6FCE55345D34ADB9586255E7AC230B4D6A3EBF64B72126B7C0132D350725D23DF317341F29D55BCC60374054D90F4504A8F2FD024100E67B8AEE106B21395CE938FD56CBDBE1F1296CDCFF74C78CE3D2C615BA98F920DC4EA587811B84BF79221AEA9296E2340BC91D349DD8EEB18D40615F73FEE6FF024100E623A6FB347A39473271B7FDAA8205D27A7B52E9549D2589C683903000AF716EDE759191204EE1DA64C14ACFA10457CDD412CA09813F38A18F16BB7C6B12B9AB024014472E53FFB1CD3C84C6283371DD81BD0140C9C92FD8906DFEE55E742EF4A286979B7BC8CE3D2392CD0F891AB646FC23E41D8FAA3F71049F2E74499CE251BCF502403542A4FF57EABD5CC3C8DB9AE21E0B38E5CDAAA78344870E7699B601D5F6C45AB333244820E10095E9616E6DD4C6CB874000452FA3F0BCAB6F1104BCCB8EDED702406E3ED705B0E7F86EF9A1B7D86B08E4803B0950D0FA3C54FD71D609F1E4F854B5DC86962A1379FCC2EB7E9B8B00E678EF87F57ABCA9EEF3F112955D00C55C6DB8";

    char pvk[1024] = { 0x0 };
    int pvk_len;
    char str[4096] =  { 0x0 };
    char *file_name = "_t_pvk.pem";
    char buff[2024] = { 0x0 };

    char* expected_pvk = "-----BEGIN RSA PRIVATE KEY-----\n\
MIICWwIBAAKBgQDPMxgMJ8M3ONFMpWEixJBv4/etQHHJKa1YRkZYC2zfZAhFbbd0\n\
EmylTEfGEeDqLhO7FX2oh4gJZbR6hBjgskhgG6zqvOqMEuLVn2VIPl5INWg1+caD\n\
MbkNuAvabGJwXH0wdd0NWfycpKdgm6U4RbQqeJso12LS5C1LruCSgyCTVQIDAQAB\n\
AoGAezc6PLhEqgk6xiau7hsQfcmGl1v0jpkfQZiA6ojY1LvLA2asqvTt8Rq8r/gf\n\
1YNTLnUoRdlbN6NowVbe6Hh8+sBuO5R5NPz/TCQXOXtvzlU0XTStuVhiVeesIwtN\n\
aj6/ZLchJrfAEy01ByXSPfMXNB8p1VvMYDdAVNkPRQSo8v0CQQDme4ruEGshOVzp\n\
OP1Wy9vh8Sls3P90x4zj0sYVupj5INxOpYeBG4S/eSIa6pKW4jQLyR00ndjusY1A\n\
YV9z/ub/AkEA5iOm+zR6OUcycbf9qoIF0np7UulUnSWJxoOQMACvcW7edZGRIE7h\n\
2mTBSs+hBFfN1BLKCYE/OKGPFrt8axK5qwJAFEcuU/+xzTyExigzcd2BvQFAyckv\n\
2JBt/uVedC70ooaXm3vIzj0jks0PiRq2Rvwj5B2Pqj9xBJ8udEmc4lG89QJANUKk\n\
/1fqvVzDyNua4h4LOOXNqqeDRIcOdpm2AdX2xFqzMyRIIOEAlelhbm3UxsuHQABF\n\
L6PwvKtvEQS8y47e1wJAbj7XBbDn+G75obfYawjkgDsJUND6PFT9cdYJ8eT4VLXc\n\
hpYqE3n8wut+m4sA5njvh/V6vKnu8/ESlV0AxVxtuA==\n\
-----END RSA PRIVATE KEY-----\n";
    
    hex_to_bin(pvk_hex, strlen(pvk_hex), pvk, &pvk_len);

    int ret = rsa_dump_pvk_to_pem_file(pvk, pvk_len, NULL, file_name);
    
    TEST_ASSERT_NOT_EQUAL(-1, ret);

    FILE* fp = fopen(file_name, "r");
    if (fp == NULL) TEST_ASSERT_EQUAL(0, -1);

    int r = fread(buff, 1, 2024, fp);
    fclose(fp);

    TEST_ASSERT_EQUAL_STRING(expected_pvk, buff);
    remove(file_name);
}

void test_rsa_dump_pvk_to_pem_file_with_password()
{
    char* pvk_hex = "3082025B02010002818100CF33180C27C33738D14CA56122C4906FE3F7AD4071C929AD584646580B6CDF6408456DB774126CA54C47C611E0EA2E13BB157DA887880965B47A8418E0B248601BACEABCEA8C12E2D59F65483E5E48356835F9C68331B90DB80BDA6C62705C7D3075DD0D59FC9CA4A7609BA53845B42A789B28D762D2E42D4BAEE0928320935502030100010281807B373A3CB844AA093AC626AEEE1B107DC986975BF48E991F419880EA88D8D4BBCB0366ACAAF4EDF11ABCAFF81FD583532E752845D95B37A368C156DEE8787CFAC06E3B947934FCFF4C2417397B6FCE55345D34ADB9586255E7AC230B4D6A3EBF64B72126B7C0132D350725D23DF317341F29D55BCC60374054D90F4504A8F2FD024100E67B8AEE106B21395CE938FD56CBDBE1F1296CDCFF74C78CE3D2C615BA98F920DC4EA587811B84BF79221AEA9296E2340BC91D349DD8EEB18D40615F73FEE6FF024100E623A6FB347A39473271B7FDAA8205D27A7B52E9549D2589C683903000AF716EDE759191204EE1DA64C14ACFA10457CDD412CA09813F38A18F16BB7C6B12B9AB024014472E53FFB1CD3C84C6283371DD81BD0140C9C92FD8906DFEE55E742EF4A286979B7BC8CE3D2392CD0F891AB646FC23E41D8FAA3F71049F2E74499CE251BCF502403542A4FF57EABD5CC3C8DB9AE21E0B38E5CDAAA78344870E7699B601D5F6C45AB333244820E10095E9616E6DD4C6CB874000452FA3F0BCAB6F1104BCCB8EDED702406E3ED705B0E7F86EF9A1B7D86B08E4803B0950D0FA3C54FD71D609F1E4F854B5DC86962A1379FCC2EB7E9B8B00E678EF87F57ABCA9EEF3F112955D00C55C6DB8";

    char pvk[1024] = { 0x0 };
    int pvk_len;
    char str[4096] =  { 0x0 };
    char *file_name = "_t_pvk.pem";
    char buff[2024] = { 0x0 };

    char* expected_pvk = "-----BEGIN RSA PRIVATE KEY-----\n\
MIICWwIBAAKBgQDPMxgMJ8M3ONFMpWEixJBv4/etQHHJKa1YRkZYC2zfZAhFbbd0\n\
EmylTEfGEeDqLhO7FX2oh4gJZbR6hBjgskhgG6zqvOqMEuLVn2VIPl5INWg1+caD\n\
MbkNuAvabGJwXH0wdd0NWfycpKdgm6U4RbQqeJso12LS5C1LruCSgyCTVQIDAQAB\n\
AoGAezc6PLhEqgk6xiau7hsQfcmGl1v0jpkfQZiA6ojY1LvLA2asqvTt8Rq8r/gf\n\
1YNTLnUoRdlbN6NowVbe6Hh8+sBuO5R5NPz/TCQXOXtvzlU0XTStuVhiVeesIwtN\n\
aj6/ZLchJrfAEy01ByXSPfMXNB8p1VvMYDdAVNkPRQSo8v0CQQDme4ruEGshOVzp\n\
OP1Wy9vh8Sls3P90x4zj0sYVupj5INxOpYeBG4S/eSIa6pKW4jQLyR00ndjusY1A\n\
YV9z/ub/AkEA5iOm+zR6OUcycbf9qoIF0np7UulUnSWJxoOQMACvcW7edZGRIE7h\n\
2mTBSs+hBFfN1BLKCYE/OKGPFrt8axK5qwJAFEcuU/+xzTyExigzcd2BvQFAyckv\n\
2JBt/uVedC70ooaXm3vIzj0jks0PiRq2Rvwj5B2Pqj9xBJ8udEmc4lG89QJANUKk\n\
/1fqvVzDyNua4h4LOOXNqqeDRIcOdpm2AdX2xFqzMyRIIOEAlelhbm3UxsuHQABF\n\
L6PwvKtvEQS8y47e1wJAbj7XBbDn+G75obfYawjkgDsJUND6PFT9cdYJ8eT4VLXc\n\
hpYqE3n8wut+m4sA5njvh/V6vKnu8/ESlV0AxVxtuA==\n\
-----END RSA PRIVATE KEY-----\n";
    
    hex_to_bin(pvk_hex, strlen(pvk_hex), pvk, &pvk_len);

    int ret = rsa_dump_pvk_to_pem_file(pvk, pvk_len, "123456", file_name);
    
    TEST_ASSERT_NOT_EQUAL(-1, ret);

    FILE* fp = fopen(file_name, "r");
    if (fp == NULL) TEST_ASSERT_EQUAL(0, -1);

    int r = fread(buff, 1, 2024, fp);
    fclose(fp);

    //TEST_ASSERT_EQUAL_STRING(expected_pvk, buff);
    remove(file_name);
}

void test_rsa_dump_pvk_to_pkcs8_pem_file()
{
    char* pvk_hex = "3082025B02010002818100CF33180C27C33738D14CA56122C4906FE3F7AD4071C929AD584646580B6CDF6408456DB774126CA54C47C611E0EA2E13BB157DA887880965B47A8418E0B248601BACEABCEA8C12E2D59F65483E5E48356835F9C68331B90DB80BDA6C62705C7D3075DD0D59FC9CA4A7609BA53845B42A789B28D762D2E42D4BAEE0928320935502030100010281807B373A3CB844AA093AC626AEEE1B107DC986975BF48E991F419880EA88D8D4BBCB0366ACAAF4EDF11ABCAFF81FD583532E752845D95B37A368C156DEE8787CFAC06E3B947934FCFF4C2417397B6FCE55345D34ADB9586255E7AC230B4D6A3EBF64B72126B7C0132D350725D23DF317341F29D55BCC60374054D90F4504A8F2FD024100E67B8AEE106B21395CE938FD56CBDBE1F1296CDCFF74C78CE3D2C615BA98F920DC4EA587811B84BF79221AEA9296E2340BC91D349DD8EEB18D40615F73FEE6FF024100E623A6FB347A39473271B7FDAA8205D27A7B52E9549D2589C683903000AF716EDE759191204EE1DA64C14ACFA10457CDD412CA09813F38A18F16BB7C6B12B9AB024014472E53FFB1CD3C84C6283371DD81BD0140C9C92FD8906DFEE55E742EF4A286979B7BC8CE3D2392CD0F891AB646FC23E41D8FAA3F71049F2E74499CE251BCF502403542A4FF57EABD5CC3C8DB9AE21E0B38E5CDAAA78344870E7699B601D5F6C45AB333244820E10095E9616E6DD4C6CB874000452FA3F0BCAB6F1104BCCB8EDED702406E3ED705B0E7F86EF9A1B7D86B08E4803B0950D0FA3C54FD71D609F1E4F854B5DC86962A1379FCC2EB7E9B8B00E678EF87F57ABCA9EEF3F112955D00C55C6DB8";

    char pvk[1024] = { 0x0 };
    int pvk_len;
    char str[4096] =  { 0x0 };
    char *file_name = "_t_pkcs8_pvk.pem";
    char buff[2024] = { 0x0 };

    char* expected_pvk = "-----BEGIN PRIVATE KEY-----\nMIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAM8zGAwnwzc40Uyl\nYSLEkG/j961AcckprVhGRlgLbN9kCEVtt3QSbKVMR8YR4OouE7sVfaiHiAlltHqE\nGOCySGAbrOq86owS4tWfZUg+Xkg1aDX5xoMxuQ24C9psYnBcfTB13Q1Z/Jykp2Cb\npThFtCp4myjXYtLkLUuu4JKDIJNVAgMBAAECgYB7Nzo8uESqCTrGJq7uGxB9yYaX\nW/SOmR9BmIDqiNjUu8sDZqyq9O3xGryv+B/Vg1MudShF2Vs3o2jBVt7oeHz6wG47\nlHk0/P9MJBc5e2/OVTRdNK25WGJV56wjC01qPr9ktyEmt8ATLTUHJdI98xc0HynV\nW8xgN0BU2Q9FBKjy/QJBAOZ7iu4QayE5XOk4/VbL2+HxKWzc/3THjOPSxhW6mPkg\n3E6lh4EbhL95IhrqkpbiNAvJHTSd2O6xjUBhX3P+5v8CQQDmI6b7NHo5RzJxt/2q\nggXSentS6VSdJYnGg5AwAK9xbt51kZEgTuHaZMFKz6EEV83UEsoJgT84oY8Wu3xr\nErmrAkAURy5T/7HNPITGKDNx3YG9AUDJyS/YkG3+5V50LvSihpebe8jOPSOSzQ+J\nGrZG/CPkHY+qP3EEny50SZziUbz1AkA1QqT/V+q9XMPI25riHgs45c2qp4NEhw52\nmbYB1fbEWrMzJEgg4QCV6WFubdTGy4dAAEUvo/C8q28RBLzLjt7XAkBuPtcFsOf4\nbvmht9hrCOSAOwlQ0Po8VP1x1gnx5PhUtdyGlioTefzC636biwDmeO+H9Xq8qe7z\n8RKVXQDFXG24\n-----END PRIVATE KEY-----\n";    

    hex_to_bin(pvk_hex, strlen(pvk_hex), pvk, &pvk_len);

    int ret = rsa_dump_pvk_to_pkcs8_pem_file(pvk, pvk_len, NULL, file_name);
    
    TEST_ASSERT_NOT_EQUAL(-1, ret);

    FILE* fp = fopen(file_name, "r");
    if (fp == NULL) TEST_ASSERT_EQUAL(0, -1);

    int r = fread(buff, 1, 2024, fp);
    fclose(fp);

    TEST_ASSERT_EQUAL_STRING(expected_pvk, buff);
    remove(file_name);
}

void test_rsa_dump_pvk_to_pkcs8_pem_file_with_password()
{
    char* pvk_hex = "3082025B02010002818100CF33180C27C33738D14CA56122C4906FE3F7AD4071C929AD584646580B6CDF6408456DB774126CA54C47C611E0EA2E13BB157DA887880965B47A8418E0B248601BACEABCEA8C12E2D59F65483E5E48356835F9C68331B90DB80BDA6C62705C7D3075DD0D59FC9CA4A7609BA53845B42A789B28D762D2E42D4BAEE0928320935502030100010281807B373A3CB844AA093AC626AEEE1B107DC986975BF48E991F419880EA88D8D4BBCB0366ACAAF4EDF11ABCAFF81FD583532E752845D95B37A368C156DEE8787CFAC06E3B947934FCFF4C2417397B6FCE55345D34ADB9586255E7AC230B4D6A3EBF64B72126B7C0132D350725D23DF317341F29D55BCC60374054D90F4504A8F2FD024100E67B8AEE106B21395CE938FD56CBDBE1F1296CDCFF74C78CE3D2C615BA98F920DC4EA587811B84BF79221AEA9296E2340BC91D349DD8EEB18D40615F73FEE6FF024100E623A6FB347A39473271B7FDAA8205D27A7B52E9549D2589C683903000AF716EDE759191204EE1DA64C14ACFA10457CDD412CA09813F38A18F16BB7C6B12B9AB024014472E53FFB1CD3C84C6283371DD81BD0140C9C92FD8906DFEE55E742EF4A286979B7BC8CE3D2392CD0F891AB646FC23E41D8FAA3F71049F2E74499CE251BCF502403542A4FF57EABD5CC3C8DB9AE21E0B38E5CDAAA78344870E7699B601D5F6C45AB333244820E10095E9616E6DD4C6CB874000452FA3F0BCAB6F1104BCCB8EDED702406E3ED705B0E7F86EF9A1B7D86B08E4803B0950D0FA3C54FD71D609F1E4F854B5DC86962A1379FCC2EB7E9B8B00E678EF87F57ABCA9EEF3F112955D00C55C6DB8";

    char pvk[1024] = { 0x0 };
    int pvk_len;
    char str[4096] =  { 0x0 };
    char *file_name = "_t_pkcs8_pvk.pem";
    char buff[2024] = { 0x0 };

    char* expected_pvk = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIC1DBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQI1hgG+7qZxr0CAggA\nMAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECD0jlGsgzEHCBIICgAOke8vnrmum\nNECV7l7HzU1zR4AOdGZjJ7QhkmgHU0cHL0Rd5l8xa6O9KIs2A7WVcYoCwoNJ31c8\nDn0x7/wZDipRh7+kSsnfv1dJHts01RfKWpiJZ7DAVtF+PJ8tMSDIgkkbaIqnXdI1\nA6XiDxowKABWAdBnyJ67hTU/HUgEGV2yrLFgn9YpX6aJDA/sD7XbwPpUUPugnBhF\nD5TK5nSJr3d4gC8/ddjG4BhdGHL/mwf542xUIiFS6Bml7VvNEiJvt+tJdFuNDebk\nItr1lu6lfbFFHQZ1UpmWXXNcXuGjPfaspcLdcufcljFJ3ohIHkr1c9qMhO4N+JLX\nmDOI+Y/JBumNpxBtstP1MOBYtcU35TzumyAs8yjiem+HW9oAUOcFnOmW8hmaVZ80\nJ2nzZNJIiHYDhMwir4iljbfHdOom9knoP+wHfPhKzVxn49EyORKffC2ZP13MCVtE\nLHES4HT2gw6IQ4iV+yi7GCIlksRxIDbyFtZ9Js5pa1MIoOy4/tkPUGs+ZBIS+Jou\nyd2I9R+imelHK7vsqPi3tpl1lVy9UZpNb/D+xC0YcJIgix2oCc8G0ZVHLE1dTnl5\n5zm/JOfFo4F98qsRWnvtoewk3/8W204szPO8wR6/2pTl7OUk8pbGUrMu1HBHRGhs\nhNXPL0x8OaZx42Nf+C+0FtIDaNFNLvE8Gr7ZbkantSh5txLQUwOrkEzENlBEZuIH\nfdVFetelnSlF2pXJx3C2wXSJKiRwDjgIATS9Vd4c0fuo0jIwmAgaNWgnAvu9nLiy\nPmza/WjJhXXOnNod1iePBEcpYEU5RlN3LIGjzzm3lvI8cZrZ1SiGlaTh+chjcB9n\nqTSOcZY08og=\n-----END ENCRYPTED PRIVATE KEY-----\n";

    hex_to_bin(pvk_hex, strlen(pvk_hex), pvk, &pvk_len);

    int ret = rsa_dump_pvk_to_pkcs8_pem_file(pvk, pvk_len, "123456", file_name);
    
    TEST_ASSERT_NOT_EQUAL(-1, ret);

    /*
    FILE* fp = fopen(file_name, "r");
    if (fp == NULL) TEST_ASSERT_EQUAL(0, -1);

    int r = fread(buff, 1, 2024, fp);
    fclose(fp);

    TEST_ASSERT_EQUAL_STRING(expected_pvk, buff);
    */
    remove(file_name);
}

void test_rsa_transfer_key_pkcs8_to_pkcs1()
{
    char *pkcs8_key_hex ="30819F300D06092A864886F70D010101050003818D0030818902818100A6D36FD33D75DDDACC3A7E978C187FC0FC57FEA133C7AA37438BEAC509874B1C621536D5F746D69E527A4E0A4B487A22E29BC2CC8D42C0AF7DE0E086CE0016452DF90CF5F470E6AAA2838F6AD4D1FCE4AB6153D850764E6B7BAF5037DA9A186B0D2763CFF843819C5AE9F149DBFCCBB33CAE9733CD040208E4690299C8A968550203010001";
    char *expected_pkcs1_key_hex = "30818902818100A6D36FD33D75DDDACC3A7E978C187FC0FC57FEA133C7AA37438BEAC509874B1C621536D5F746D69E527A4E0A4B487A22E29BC2CC8D42C0AF7DE0E086CE0016452DF90CF5F470E6AAA2838F6AD4D1FCE4AB6153D850764E6B7BAF5037DA9A186B0D2763CFF843819C5AE9F149DBFCCBB33CAE9733CD040208E4690299C8A968550203010001";
    
    char pkcs8_bin[1024] = { 0x0 };
    int pkcs8_bin_len = 0;

    char pkcs1_key[1024] = { 0x0 };

    char pkcs1_key_hex[512] = { 0x0 };
    int pkcs1_key_hex_len = 0;

    hex_to_bin(pkcs8_key_hex, strlen(pkcs8_key_hex), pkcs8_bin, &pkcs8_bin_len);
    
    int pkcs1_key_len = rsa_transfer_key_pkcs8_to_pkcs1(pkcs8_bin, pkcs8_bin_len, pkcs1_key);

    bin_to_hex(pkcs1_key, pkcs1_key_len, pkcs1_key_hex, &pkcs1_key_hex_len);

    TEST_ASSERT_EQUAL_STRING(expected_pkcs1_key_hex, pkcs1_key_hex);
}

int main(int argc, char* argv[]) {

    setupdata();

    UNITY_BEGIN();

    RUN_TEST(test_sm2_read_pvk_from_pemfile);
    RUN_TEST(test_sm2_read_pvk_from_pem_str);
    
    RUN_TEST(test_sm2_read_puk_from_pemfile);
    RUN_TEST(test_sm2_read_puk_from_pem_str);
    
    RUN_TEST(test_remove_format_from_cipher_text);
    RUN_TEST(test_encode_cipher_text);

    RUN_TEST(test_des_ecb_encrypt);
    RUN_TEST(test_des_ecb_decrypt);

    RUN_TEST(test_des_cbc_encrypt);
    RUN_TEST(test_des_cbc_decrypt);
    
    RUN_TEST(test_rsa_read_key_from_pem_file);
    RUN_TEST(test_rsa_read_key_from_pem_str);
    RUN_TEST(test_rsa_encrypt);
    RUN_TEST(test_rsa_decrypt);
    RUN_TEST(test_rsa_sign);
    RUN_TEST(test_rsa_verify);

    RUN_TEST(test_bas64_to_bin);
    RUN_TEST(test_bin_to_bas64);

    RUN_TEST(test_rsa_generate_key);
    RUN_TEST(test_rsa_dump_puk_to_pem_str);
    RUN_TEST(test_rsa_dump_puk_to_pkcs8_pem_str);
    RUN_TEST(test_rsa_dump_pvk_to_pem_str);
    RUN_TEST(test_rsa_dump_pvk_to_pkcs8_pem_str);
    RUN_TEST(test_rsa_dump_pvk_to_pkcs8_pem_str_with_password);
    
    RUN_TEST(test_rsa_dump_puk_to_pem_file);
    RUN_TEST(test_rsa_dump_puk_to_pkcs8_pem_file);

    RUN_TEST(test_rsa_dump_pvk_to_pem_file);
    RUN_TEST(test_rsa_dump_pvk_to_pem_file_with_password);
    RUN_TEST(test_rsa_dump_pvk_to_pkcs8_pem_file);
    RUN_TEST(test_rsa_dump_pvk_to_pkcs8_pem_file_with_password);

    RUN_TEST(test_rsa_transfer_key_pkcs8_to_pkcs1);
    
    // test key exchange
    RUN_TEST(test_cb_kx_keypair);
    RUN_TEST(test_cb_kx_random_bufpair);
    RUN_TEST(test_cb_kx_svr_session_key);
    RUN_TEST(test_cb_kx_clt_session_key);
    RUN_TEST(test_cb_kx_dh_session_key);

    // test sm2
    RUN_TEST(test_cb_sm2_keypair);
    RUN_TEST(test_cb_sm2_encrypt);
    RUN_TEST(test_cb_sm2_decrypt);
    RUN_TEST(test_cb_sm2_compute_key);
    RUN_TEST(test_cb_sm2_compress_public_key);
    RUN_TEST(test_cb_sm2_uncompress_public_key);
    RUN_TEST(test_cb_sm2_compute_puk);
    RUN_TEST(test_cb_sm2_sign);
    RUN_TEST(test_cb_sm2_sign_verify);

    // test secret box
    RUN_TEST(test_cb_secretbox_keygen);
    RUN_TEST(test_cb_secretbox_easy);
    RUN_TEST(test_cb_secretbox_open_easy);
    RUN_TEST(test_cb_secretbox_auth);
    RUN_TEST(test_cb_secretbox_auth_verify);

    // test sm4
    RUN_TEST(test_cb_sm4_mac);
    RUN_TEST(test_cb_sm4_mac_verify);
    
    RUN_TEST(test_cb_sm4_ecb_encrypt);
    RUN_TEST(test_cb_sm4_ecb_decrypt);

    RUN_TEST(test_cb_sm4_cbc_encrypt);
    RUN_TEST(test_cb_sm4_cbc_decrypt);

    // test kdf
    RUN_TEST(test_cb_kdf_derive_from_key);

    // test sm3
    RUN_TEST(test_cb_sm3_digest);

    // test publicbox
    RUN_TEST(test_cb_publicbox_seal);
    RUN_TEST(test_cb_publicbox_seal_open);

    cleanup();

    UNITY_END();

    return 0;
}
