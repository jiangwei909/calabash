//
// Created by jiangwei on 2017/11/29.
//

#ifndef SM2_H
#define SM2_H

#define DIGEST_NONE 	0x0
#define DIGEST_MD5  	0x4
#define DIGEST_SHA1 	0x64
#define DIGEST_SHA224 	0x675
#define DIGEST_SHA256 	0x672
#define DIGEST_SHA384 	0x673
#define DIGEST_SHA512 	0x674

#define CB_SM2_PUBLICKEY_BYTES 65
#define CB_SM2_SECRETKEY_BYTES 32
#define CB_SM3_DIGEST_BYTES 32
#define CB_SM2_COMPRESS_PUBLICKEY_BYTES 33

/**
 * @brief 压缩SM2国密算法的公钥
 * @details 对SM2国密算法的公钥进行压缩
 * 
 * @param puk SM2国密算法的公钥,支持04开头的长度为65字节密钥或是64字节的密钥
 * @param puk_len 必须是64或者65, 如果长度是65,公钥的第一个字节必须是0x04
 * @param compressed_puk 压缩后的公钥,压缩后的公钥以0x02或者0x03开头,长度固定为33
 * @return 成功返回0, 否则表示失败
 */
int cb_sm2_compress_public_key(const char *puk, int puk_len, char *compressed_puk);

/**
 * @brief 还原SM2国密算法的公钥为未压缩
 * @details 对压缩的SM2国密算法公钥进行还原
 * 
 * @param puk 待还原的SM2国密算法的公钥,必须以0x02或者0x03开头,长度固定为33
 * @param decompressed_puk 还原后的公钥,以0x04开头,长度固定为65
 * @return 成功返回0, 否则表示失败
 */
int cb_sm2_uncompress_public_key(const char *puk, char *decompressed_puk);

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
 *  @brief 生成SM2公私密钥对
 *  @details 生成一组SM2公私密钥对
 * 
 *  @param pk 生成的公钥，未经压缩，以0x04开头
 *  @param sk 生成的私钥
 *  @return 成功返回0，否则表示失败
 */
int cb_sm2_keypair(char* pk, char* sk);

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

int cb_sm2_encrypt(const char* pk, const char* plain, int plain_len, char* cipher);
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


int cb_sm2_decrypt(const char* pk, const char* cipher, int cipher_len, char* plain);

/**
 *  @brief 计算SM3摘要
 *  @details 计算SM3摘要
 *
 *  @param data 待计算的数据
 *  @param data_len 待计算的数据长度
 *  @param digest 摘要值,固定长度32
 *  @return 成功返回0，否则表示失败
 */
int cb_sm3_digest(const char* data, int data_len, char* digest);

int cb_sm2_compute_key(const char* private_key, const char* public_key, char* key);

#endif //CALABASH_H
