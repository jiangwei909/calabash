#include "internal.h"

int encode_cipher_text(const char* cipher, int cipher_len, char* encoded_cipher, int* encoded_cipher_len)
{
    int total_length = 0;
    int offset = 0;
    char buffer[512] = { 0x0 };
    
    for (int i = 0; i < 4; i++) {
	if (i < 2) {
	    buffer[offset] = 0x02;
	} else {
	    buffer[offset] = 0x04;
	}
	offset += 1;
	
	if (i < 3) {
	    if ((*(cipher + 32*i) & 0x80) > 0 ) {
		buffer[offset] = 0x21;
		offset += 1;
		buffer[offset] = 0x00;
		offset += 1;
	    } else {
		buffer[offset] = 0x20;
		offset += 1;
	    }
	    
	    memcpy(buffer + offset, cipher + i*32, 32);
	    offset += 32;
	} else {
	    buffer[offset] = (cipher_len - 96);
	    offset += 1;
	    memcpy(buffer + offset, cipher + i*32, cipher_len - 96);
	    offset += (cipher_len - 96);
	}
    }

    total_length = offset;
    offset = 0;

    encoded_cipher[0] = 0x30;
    offset += 1;
    
    if (total_length > 127) {
	encoded_cipher[1] = 0x81;
	encoded_cipher[2] = total_length;
	offset += 2;
    } else {
	encoded_cipher[1] = total_length;
	offset += 1;
    }

    memcpy(encoded_cipher + offset, buffer, total_length);
    offset += total_length;

    *encoded_cipher_len = offset;
    
    return 0;
}
