#ifndef TEST_SM2_H
#define TEST_SM2_H

void test_cb_sm2_keypair();
void test_cb_sm2_encrypt();
void test_cb_sm2_encrypt2();
void test_sm2_encrypt4();

void test_cb_sm2_decrypt();
void test_cb_sm2_compute_key();

void test_cb_sm2_compress_public_key();
void test_cb_sm2_uncompress_public_key();
void test_cb_sm2_get_puk_from_pvk();

void test_cb_sm2_sign();
void test_cb_sm2_sign_verify();

#endif // !TEST_SM2_H