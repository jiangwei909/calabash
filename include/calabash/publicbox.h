#ifndef PUBLICBOX_H
#define PUBLICBOX_H

/**
 * @brief 采用信封形式加密数据
 * @details 采用信封形式加密数据,采用SM2和SM4算法
 *
 * @param pk 公开密钥
 * @param data 待加密的数据
 * @param data_len 待加密数据的长度
 * @param cipher 生成的加密数据
 * @return 返回加密数据的长度
 */
int cb_publicbox_seal(const char* pk, const char* data, unsigned int data_len, char* cipher);

int cb_publicbox_seal_open(const char* pk, const char* data, unsigned int data_len, char* plain);

#endif // !PUBLICBOX_H