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

#include "calabash.h"

int base64_to_bin(const char *src, int src_len, char *dst)
{
    BIO *b64, *bio;
    BUF_MEM *bptr = NULL;
    int counts;
    int size = 0;

    if (src == NULL || dst == NULL)
        return -1;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bio = BIO_new_mem_buf(src, src_len);
    bio = BIO_push(b64, bio);

    size = BIO_read(bio, dst, src_len);

    BIO_free_all(bio);
    return size;
}
