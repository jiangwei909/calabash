#ifndef SECRETBOX_H
#define SECRETBOX_H

#define CB_SECRETBOX_KEY_BYTES 16
#define CB_SECRETBOX_CIPHER_MIN_BYTES 32
#define CB_SECRETBOX_MAC_BYTES 16
#define CB_SECRETBOX_AUTHMAC_BYTES 32
/**
 * @brief 生成秘密密钥
 * @details 生成秘密密钥
 *
 * @param key 生成的秘密密钥
 * 
 */
void cb_secretbox_keygen(char* key);

/**
 * @brief 生成待校验的加密数据
 * @details 生成待校验的加密数据
 *
 * @param sk 秘密密钥
 * @param data 待加密的数据
 * @param data_len 待加密数据的长度
 * @param cipher 生成的加密数据
 * @return 返回加密数据的长度
 */
int cb_secretbox_easy(const char* sk, const char* data, unsigned int data_len, char* cipher);

/**
 * @brief 验证并解密数据
 * @details 验证并解密数据
 *
 * @param sk 秘密密钥
 * @param data 待解密的数据
 * @param data_len 待解密数据的长度
 * @param plain 解密后的数据
 * @return 返回解密后数据的长度
 */
int cb_secretbox_open_easy(const char* sk, const char* data, unsigned int data_len, char* plain);

/**
 * @brief 生成消息认证码
 * @details 生成消息认证码,算法采用HMAC-SM3
 *
 * @param sk 秘密密钥
 * @param data 待解密的数据
 * @param data_len 待解密数据的长度
 * @param plain 消息认证码
 * @return 返回消息认证码的长度
 */
int cb_secretbox_auth(const char* sk, const char* data, unsigned int data_len, char* mac);

#endif // !SECRETBOX_H