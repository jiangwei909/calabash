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
    int nl_flag = 0;
    char *tmp_buff = NULL;
    
    if (src == NULL || dst == NULL)
        return -1;

    tmp_buff = (char*)malloc(src_len);

    int j = 0;
    for(int i = 0; i< src_len; i++) {
	if (src[i] == 0x0A || src[i] == 0x0D || src[i] == 0x20) continue;
	tmp_buff[j] = src[i];
	j += 1;
    }
	    
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bio = BIO_new_mem_buf(tmp_buff, j);
    bio = BIO_push(b64, bio);

    size = BIO_read(bio, dst, src_len);

    BIO_free_all(bio);
    free(tmp_buff);
    
    return size;
}

int bin_to_base64(const char *src, int src_len, int newline_flag, char *dst)
{
    BIO *b64, *bio;
    BUF_MEM *bptr = NULL;
    size_t size = 0;

    if (src == NULL || dst == NULL)
	return -1;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());

    if (newline_flag == 0x0) {
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }
    
    bio = BIO_push(b64, bio);

    BIO_write(bio, src, src_len);
    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &bptr);
    memcpy(dst, bptr->data, bptr->length);

    size = bptr->length;
    
    BIO_free_all(bio);
    return size;
}
