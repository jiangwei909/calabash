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

#include "calabash/sm2.h"

#include "calabash/kdf.h"


int cb_kdf_derive_from_key(const char* master_key, unsigned int subkey_id, const char* context, unsigned int subkey_size, char* subkey)
{
    char* tmp_buff = NULL;
    char tmp_in[32] = { 0x0 };
    int context_len = strlen(context);


    int round = (subkey_size / 32 ) + 1;

    if (context_len > 16) context_len = 16;
    if (round > 16) return -1;

    sprintf(tmp_in, "%08X", subkey_id);
    memcpy(tmp_in + 8, context, context_len);

    tmp_buff = malloc(round*32);

    for(int i = 0; i < round; i++) {
        memcpy(tmp_in + 8 + context_len, master_key, 16);
        tmp_in[8 + context_len + 16] = i & 0xFF;

        cb_sm3_digest(tmp_in, 8 + context_len + 16 + 1, tmp_buff + (i*32));
    }
    
    memcpy(subkey, tmp_buff, subkey_size);

    return 0;
}
