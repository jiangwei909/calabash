//
// Created by jiangwei on 2017/11/29.
//

#ifndef CALABASH_H
#define CALABASH_H

/**
 * @brief 将16进制的字符串转换为2进制字符序列
 * @details 将16进制的字符串转换为2进制字符序列,
 * 通常两个16进制字符转换成一个2进制字符,例如,"30"将转换成ASCII码为0x30的字符。
 * 
 * @param src 待转换的16进制的字符串
 * @param src_len 待转换的16进制的字符串的长度
 * @param dst 转换后的2进制字符序列
 * @param dst_len 转换后的2进制字符序列长度 
 * @return 成功返回0，否则表示失败
 */
int hex_to_bin(const char *src, int src_len, char *dst, int *dst_len);

/**
 * @brief 将2进制的字符串转换为16进制字符序列
 * @details 将2进制的字符串转换为16进制字符序列,
 * 通常一个2进制字符转换成两个16进制字符,例如,ASCII码为0x30的字符将转换成"30"。
 * 
 * @param src 待转换的2进制的字符串
 * @param src_len 待转换的2进制的字符串的长度
 * @param dst 转换后的16进制字符序列
 * @param dst_len 转换后的16进制字符序列长度 
 * @return 成功返回0, 否则表示失败
 */
int bin_to_hex(const char *src, int src_len, char *dst, int *dst_len);

int read_private_key_from_pem(const char *pemfile, unsigned char *private_key,
                              int *private_key_len);

/**
 * @brief 压缩SM2国密算法的公钥
 * @details 对SM2国密算法的公钥进行压缩
 * 
 * @param puk SM2国密算法的公钥,支持04开头的长度为65字节密钥或是64字节的密钥
 * @param puk_len 必须是64或者65, 如果长度是65,公钥的第一个字节必须是0x04
 * @param compressed_puk 压缩后的公钥,压缩后的公钥以0x02或者0x03开头
 * @param compressed_puk_len 压缩后的公钥长度,长度固定为33
 * @return 成功返回0, 否则表示失败
 */
int sm2_compress_public_key(const char *puk, int puk_len, char *compressed_puk,
                            int *compressed_puk_len);

/**
 * @brief 还原SM2国密算法的公钥
 * @details 对压缩的SM2国密算法公钥进行还原
 * 
 * @param puk 待还原的SM2国密算法的公钥,必须以0x02或者0x03开头
 * @param puk_len 必须等于33
 * @param uncompress_puk 还原后的公钥,以0x04开头
 * @param uncompress_puk_len 还原后的公钥,长度固定为65
 * @return 成功返回0, 否则表示失败
 */
int sm2_uncompress_public_key(const char *puk, int puk_len,
                              char *uncompress_puk, int *uncompress_puk_len);

int sm2_sign_with_pem(const unsigned char *pvk, int pvk_len, const char *data,
                      int data_len, char *signature, int *len);

int sm2_sign(const char *pvk, int pvk_len, const char *data,
             int data_len, char *signature, int *signature_len);

int sm2_sign_verify(const unsigned char *puk, int puk_len, const unsigned char *data,
                    int data_len, const unsigned char *signature, int sig_len);


int sm2_get_puk_from_pvk(const char* pvk, int pvk_len, char* puk, int* puk_len);

/**
 *  @brief 生成公私密钥对
 *  @details 生成一组SM2公私密钥对
 * 
 *  @param pvk 生成的私钥
 *  @param pvk_len 生成的私钥的长度
 *  @param puk 生成的公钥，以0x04开头
 *  @param puk_len 生成的公钥长度
 *  @return 成功返回0，否则表示失败
 */
int sm2_generate_keypair(char* pvk, int* pvk_len, char* puk, int* puk_len);
			 
#endif //CALABASH_H
