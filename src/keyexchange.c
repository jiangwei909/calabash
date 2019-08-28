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

int cb_kx_keypair(char* pk, char* sk)
{
    EC_KEY* ec_key = NULL;
    int ret = -1;
    BIGNUM* bn_pvk = NULL;
    EC_POINT* puk_point = NULL;
    EC_GROUP *curve_group = NULL;
    
    ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);    
    ret = EC_KEY_generate_key(ec_key);

    if (ret == 0) return -1;

    bn_pvk = EC_KEY_get0_private_key(ec_key);
    BN_bn2bin(bn_pvk, sk);
    BN_free(bn_pvk);

    puk_point = EC_KEY_get0_public_key(ec_key);
    curve_group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);

    ret = EC_POINT_point2oct(curve_group, puk_point,
			     POINT_CONVERSION_UNCOMPRESSED,
			     pk, 65, NULL);

    EC_POINT_free(puk_point);
    EC_GROUP_free(curve_group);
    // EC_KEY_free(ec_key);

    if (ret < 0) return ret;

    return 0;
}

int cb_kx_random_bufpair(const char* pk, char* rnd, char* pk_rnd)
{
    return -1;
}

int cb_kx_svr_session_keys(const char* sk, const char* rx_rnd, const char* tx_pk_rnd, char* rx, char* tx)
{
    return -1;
}

int cb_kx_clt_session_keys(const char* rx_rnd, const char* tx_rnd, char* rx, char* tx)
{
    return -1;
}