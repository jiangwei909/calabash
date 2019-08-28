#include <string.h>
#include <stdlib.h>

#ifdef WIN32
#include <io.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif // WIN32

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/gmapi.h>
#include <openssl/sms4.h>

#include "calabash/keyexchange.h"
#include "calabash/utils.h"
#include "calabash/sm2.h"

int cb_kx_keypair(char* pk, char* sk)
{
    return cb_sm2_keypair(pk, sk);
}

int cb_kx_random_bufpair(const char* pk, char* rnd, char* pk_rnd)
{
    RAND_bytes(rnd, CB_KX_RANDOM_BYTES);

    int ret = cb_sm2_encrypt(pk, rnd, CB_KX_RANDOM_BYTES, pk_rnd);

    cb_debug("ret=%d\n", ret);

    if (ret != CB_KX_PK_RANDOM_BYTES) return -1;

    return 0;
}

int cb_kx_svr_session_keys(const char* sk, const char* rx_rnd, const char* pk_tx_rnd, char* rx, char* tx)
{
    char tx_rnd[CB_KX_RANDOM_BYTES] = { 0x0 };
    int ret = cb_sm2_decrypt(sk, pk_tx_rnd, CB_KX_PK_RANDOM_BYTES, tx_rnd);
cb_debug("ret=%d\n", ret);
    if (ret != CB_KX_RANDOM_BYTES) return -1;

    // 服务端的密钥和客户端的相反，需要调换位置
    return cb_kx_clt_session_keys(rx_rnd, tx_rnd, tx, rx);
}

int cb_kx_clt_session_keys(const char* rx_rnd, const char* tx_rnd, char* rx, char* tx)
{
    char* head = "3081";
    char tmp[48] = { 0x0 };
    char digest[32] = { 0x0 };

    memcpy(tmp, head, 4);
    memcpy(tmp + 4, rx_rnd, CB_KX_RANDOM_BYTES);
    memcpy(tmp + 4 + CB_KX_RANDOM_BYTES, tx_rnd, CB_KX_RANDOM_BYTES);

    sm3(tmp, CB_KX_RANDOM_BYTES*2 + 4, digest);

    memcpy(rx, digest, 16);
    memcpy(tx, digest + 16, 16);

    return 0;
}