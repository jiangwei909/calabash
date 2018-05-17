//
// Created by jiangwei on 2017/11/29.
//

#ifndef CALABASH_H
#define CALABASH_H

int hexToBin(const char *src, int src_len, char *dst, int *dst_len);
int binToHex(const char *src, int src_len, char *dst, int *dst_len);

int read_private_key_from_pem(const char *pemfile, unsigned char *private_key,
                              int *private_key_len);

int sm2_compress_public_key(const char *puk, int puk_len, char *compressed_puk,
                        int *compressed_puk_len);
int sm2_uncompress_public_key(unsigned char *in, int in_len,
                          unsigned char *out, int *out_len);

int sm2_sign_with_pem(const unsigned char *pvk, int pvk_len, const char *data,
             int data_len, char *signature, int *len);

int sm2_sign(const unsigned char *pvk, int pvk_len, const char *data,
             int data_len, char *signature, int *len);

int sm2_sign_verify(const unsigned char *puk, int puk_len, const unsigned char *data,
                    int data_len, const unsigned char *signature, int sig_len);


#endif //CALABASH_H
