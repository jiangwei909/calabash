#ifndef SM4_H
#define SM4_H

#define CB_SM4_KEY_BYTES 16
#define CB_SM4_MAC_BYTES 16

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

int cb_sm4_cbc_encrypt(const char* key, const char* iv, const char* plain, int plain_len, char* cipher);

/**
 *  @brief SM4进行CBC解密
 *  @details SM4进行CBC解密, 待解密的数据长度必须是16的倍数
 *
 *  @param key 密钥的明文,必须16字节长
 *  @param iv 初始化向量,必须16字节长
 *  @param cipher 待解密的数据明文
 *  @param cipher_len 待解密的数据密文长度
 *  @param plain 解密后的明文
 *  @return 返回解密后明文的长度，负数表示失败
 */
int sm4_cbc_decrypt(const char* key, const char* iv, const char* cipher, int cipher_len, char* plain);

int cb_sm4_cbc_decrypt(const char* key, const char* iv, const char* cipher, int cipher_len, char* plain);

int cb_sm4_mac(const char* key, const char* iv, const char* cipher, int cipher_len, char* mac);

int cb_sm4_mac_verify(const char* key, const char* iv, const char* data, int data_len, const char* mac);

#endif // !SM4_H