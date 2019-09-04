#ifndef KEYEXCHANGE_H
#define KEYEXCHANGE_H

#define CB_KX_PUBLICKEY_BYTES   65
#define CB_KX_SECRETKEY_BYTES   32
#define CB_KX_RANDOM_BYTES      16
#define CB_KX_PK_RANDOM_BYTES (CB_KX_RANDOM_BYTES + 96)
#define CB_KX_SESSIONKEY_BYTES  16

/**
 * @brief 生成密钥对
 * @details 生成密钥对
 *
 * @param pk 公钥，公开的密钥
 * @param sk 私钥，秘密的密钥
 * @return 0成功表示，其他表示失败
 * 
 */
int cb_kx_keypair(char* pk, char* sk);

/**
 * @brief 生成随机数的明文和密文
 * @details 生成一对随机数的明文和密文，其中密文由SM2公钥对随机数明文加密得到
 *
 * @param pk SM2公钥，公开的密钥
 * @param rnd 随机数的明文
 * @param pk_rnd 随机数的密文
 * @return 0成功表示，其他表示失败
 * 
 */
int cb_kx_random_bufpair(const char* pk, char* rnd, char* pk_rnd);

/**
 * @brief 生成服务端的会话密钥
 * @details 在服务端（拥有私钥的端）生成一对会话密钥
 *
 * @param sk SM2私钥
 * @param rx_rnd 随机数的明文,由服务端提供
 * @param tx_pk_rnd 随机数的密文,由sk对应的公钥加密,由客户端提供
 * @param key 会话密钥，用于对数据进行加密解密
 * @return 0成功表示，其他表示失败
 * 
 */
int cb_kx_svr_session_key(const char* sk, const char* rx_rnd, const char* tx_pk_rnd, char* key);

/**
 * @brief 生成客户端的会话密钥
 * @details 在客户端生成一对会话密钥
 *
 * @param sk SM2私钥
 * @param rx_rnd 随机数的明文,由服务端提供
 * @param tx_rnd 随机数的明文,由客户端提供
 * @param rx 会话密钥，用于对数据进行加密解密
 * @return 0成功表示，其他表示失败
 * 
 */
int cb_kx_clt_session_key(const char* rx_rnd, const char* tx_rnd, char* key);

int cb_kx_dh_session_key(const char* sk, const char* peer_pk, char* key);

#endif // !KEYEXCHANGE_H
