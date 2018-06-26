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

int base64_to_bin(const char *src, int src_len, char *dst);
int bin_to_base64(const char *src, int src_len, int nl_flag, char *dst);

/**
 *  @brief 从pem文件读取SM2私钥
 *  @details 从pem文件读取SM2私钥
 *  
 *  @param pemfile pem文件路径
 *  @param pvk 从pem文件中返回的sm2私钥
 *  @param pvk_len 从pem文件中返回的sm2私钥长度，固定为32
 *  @return 成功返回0, 否则表示失败
 */
int sm2_read_pvk_from_pemfile(const char *pemfile, char *pvk, int *pvk_len);

/**
 *  @brief 从pem文件读取SM2公钥
 *  @details 从pem文件读取SM2公钥
 *  
 *  @param pemfile pem文件路径
 *  @param pvk 从pem文件中返回的sm2公钥
 *  @param pvk_len 从pem文件中返回的sm2公钥长度，通常为64字节
 *  @return 成功返回0, 否则表示失败
 */

int sm2_read_puk_from_pemfile(const char *pemfile, char *puk, int *puk_len);

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


/**
 * @brief 从私钥中获取公钥
 * @details 从SM2私钥中获取公钥

 * @param pvk 私钥
 * @param pvk_len 私钥长度
 * @param puk 返回的公钥
 * @param puk_len 返回公钥的长度
 * @return 成功返回0，否则表示失败
 */
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

/**
 *  @brief 使用公钥对数据进行加密
 *  @details 使用公钥对数据进行加密, 加密的结果为C1||C3||C2，C1是椭圆上点，C3是SM3摘要结果，C2是数据密文。C1长度为64字节（X长32字节，Y长32字节)，C3为32字节
 * 
 *  @param puk SM2公钥，用于对数据进行加密
 *  @param puk_len SM2公钥长度
 *  @param plain 待加密数据 
 *  @param plain_len 待加密数据长度
 *  @param cipher 加密后的数据密文
 *  @param cipher_len 加密后的数据密文长度
 *  @return 成功返回0，否则表示失败
 */
int sm2_encrypt(const char* puk, int puk_len, const char* plain, int plain_len, char* cipher, int* cipher_len);

/**
 *  @brief 使用SM2私钥对数据进行加密
 *  @details 使用SM2私钥对数据进行加密
 * 
 *  @param pvk SM2私钥，用于对数据进行加密
 *  @param pvk_len SM2私钥长度
 *  @param cipher 待解密数据,数据形式为C1||C3||C2，C1是椭圆上点，C3是SM3摘要结果，C2是数据密文。C1长度为64字节（X长32字节，Y长32字节)，C3为32字节
 *  @param cipher_len 待解密数据长度
 *  @param plain 解密后的数据明文
 *  @param plain_len 解密后的数据明文长度
 *  @return 成功返回0，否则表示失败
 */
int sm2_decrypt(const char* pvk, int pvk_len, const char* cipher, int cipher_len, char* plain, int* plain_len);

/**
 *  @brief 计算SM3摘要
 *  @details 计算SM3摘要
 *
 *  @param data 待计算的数据
 *  @param data_len 待计算的数据长度
 *  @param digest 摘要值,固定长度32
 *  @return 成功返回0，否则表示失败
 */
int sm3_digest(const char* data, int data_len, char* digest);


/**
 *  @brief SM4进行ECB加密
 *  @details SM4进行ECB加密, 待加密的数据长度必须是16的倍数，如不足，需要调用者填充到16的倍数
 *
 *  @param key 密钥的明文,必须16字节长
 *  @param plain 待加密的数据明文
 *  @param plain_len 待加密的数据明文长度
 *  @param cipher 加密后的密文
 *  @return 返回加密后密文的长度，负数表示失败
 */
int sm4_ecb_encrypt(const char* key, const char* plain, int plain_len, char* cipher);

/**
 *  @brief SM4进行ECB解密
 *  @details SM4进行ECB解密, 待解密的数据长度必须是16的倍数
 *
 *  @param key 密钥,必须16字节长
 *  @param cipher 待解密的数据密文
 *  @param cipher_len 待解密的数据密文长度
 *  @param plain 解密后的明文
 *  @return 返回解密后明文的长度，负数表示失败
 */
int sm4_ecb_decrypt(const char* key, const char* cipher, int cipher_len, char* plain);

/**
 *  @brief SM4进行CBC加密
 *  @details SM4进行CBC加密, 待加密的数据长度必须是16的倍数，如不足，需要调用者填充到16的倍数
 *
 *  @param key 密钥的明文,必须16字节长
 *  @param iv 初始化向量,必须16字节长
 *  @param plain 待加密的数据明文
 *  @param plain_len 待加密的数据明文长度
 *  @param cipher 加密后的密文
 *  @return 返回加密后密文的长度，负数表示失败
 */
int sm4_cbc_encrypt(const char* key, const char* iv, const char* plain, int plain_len, char* cipher);

/**
 *  @brief SM4进行CBC解密
 *  @details SM4进行CBC解密, 待解密的数据长度必须是16的倍数
 *
 *  @param key 密钥的明文,必须16字节长
 *  @param iv 初始化向量,必须16字节长
 *  @param cipher 待解密的数据明文
 *  @param cipher_len 待加密的数据明文长度
 *  @param plain 加密后的密文
 *  @return 返回解密后解文的长度，负数表示失败
 */
int sm4_cbc_decrypt(const char* key, const char* iv, const char* cipher, int cipher_len, char* plain);


int des_ecb_encrypt(const char* key, unsigned int key_len, const char* plain, int plain_len, char* cipher);

int des_ecb_decrypt(const char* key, unsigned int key_len, const char* cipher, int plain_len, char* plain);


int rsa_read_puk_from_pem_file(const char* pem_file, char* puk);
int rsa_decode_key_from_pem_str(const char* pem_str, int pem_str_len, char* puk);

int rsa_generate_key(int bits, char* pvk, int* pvk_len, char* puk, int * puk_len);
int rsa_encode_puk_to_pem_str(const char* puk, int puk_len, char* str);
int rsa_encode_pvk_to_pem_str(const char* pvk, int pvk_len, char* str);

int rsa_encode_puk_to_pem_file(const char* puk, int puk_len, char* file_name);

int rsa_encrypt(const char* puk, int puk_len, const char* plain, int plain_len, char* cipher);

int rsa_decrypt(const char* pvk, int pvk_len, const char* cipher, int cipher_len, char* plain);

int rsa_sign(const char* pvk, int pvk_len, const char* msg, int msg_len, char* sign);
int rsa_verify(const char* puk, int puk_len, const char* msg, int msg_len, const char* sign, int sign_len);
#endif //CALABASH_H
