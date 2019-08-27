#ifndef DES_H
#define DES_H

/**
 *  @brief DES进行ECB加密
 *  @details DES进行ECB加密, 密钥长度支持8/16/24字节，待加密的数据长度必须是8的倍数
 *
 *  @param key 密钥的明文,长度支持8/16/24字节
 *  @param plain 待加密的数据明文
 *  @param plain_len 待加密的数据明文长度
 *  @param cipher 加密后的密文
 *  @return 返回加密后的密文长度，负数表示失败
 */
int des_ecb_encrypt(const char* key, unsigned int key_len, const char* plain, int plain_len, char* cipher);

/**
 *  @brief DES进行ECB解密
 *  @details DES进行ECB解密, 密钥长度支持8/16/24字节，待解密的数据长度必须是8的倍数
 *
 *  @param key 密钥的明文,长度支持8/16/24字节
 *  @param cipher 待解密的数据密文
 *  @param cipher_len 待解密的数据密文长度
 *  @param plain 解密后的明文
 *  @return 返回解密后的明文长度，负数表示失败
 */
int des_ecb_decrypt(const char* key, unsigned int key_len, const char* cipher, int plain_len, char* plain);

/**
 *  @brief DES进行CBC加密
 *  @details DES进行CBC加密, 密钥长度支持8/16/24字节，待加密的数据长度必须是8的倍数
 *
 *  @param key 密钥的明文,长度支持8/16/24字节
 *  @param key_len 密钥长度支持
 *  @param iv 初始化向量, 必须是8个字节
 *  @param plain 待加密的数据明文
 *  @param plain_len 待加密的数据明文长度
 *  @param cipher 加密后的密文
 *  @return 返回加密后的密文长度，负数表示失败
 */
int des_cbc_encrypt(const char* key, unsigned int key_len, const char* iv, const char* plain, int plain_len, char* cipher);

/**
 *  @brief DES进行CBC解密
 *  @details DES进行CBC解密, 密钥长度支持8/16/24字节，待解密的数据长度必须是8的倍数
 *
 *  @param key 密钥的明文,长度支持8/16/24字节
 *  @param key_len 密钥长度支持
 *  @param iv 初始化向量, 必须是8个字节
 *  @param cipher 待解密的数据密文
 *  @param cipher_len 待解密的数据密文长度
 *  @param plain 解密后的明文
 *  @return 返回解密后的明文长度，负数表示失败
 */
int des_cbc_decrypt(const char* key, unsigned int key_len, const char* iv, const char* cipher, int cipher_len, char* plain);

#endif // !DES_H
