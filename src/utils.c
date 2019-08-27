#include <string.h>
#include "calabash/utils.h"

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

int decode_cipher_text(const unsigned char* cipher_text, int cipher_text_len,
				   unsigned char* no_fmt_string, int* no_fmt_string_len)
{
    int char_of_length = 0;
    int length_of_content = 0;
    int offset = 0;
    
    if (cipher_text[0] != 0x30 ) return -1;

    if (cipher_text[1] > 0x80) {
	char_of_length = cipher_text[1] - 0x80;
	switch(char_of_length) {
	case 1:
	    length_of_content = cipher_text[2];
	    offset = 3;
	    break;
	case 2:
	    length_of_content = cipher_text[2]*256 + cipher_text[3];
	    offset = 4;
	    break;
	case 3:
	    length_of_content = cipher_text[2]*256*256 + cipher_text[3]*256 + cipher_text[4];
	    offset = 5;
	    break;
	}
		
    } else {
	length_of_content = cipher_text[1];
	offset = 2;
    }

    if (length_of_content + offset != cipher_text_len) return -2;

    offset += 1;
    *no_fmt_string_len = 0;
    for (int i = 0; i < 4; i++) {
	
	int length_of_c1x = *(cipher_text+offset);
	offset +=1;
	if (i < 3) {
	    if (length_of_c1x > 32) {
		offset += 1;
	    }
	    length_of_c1x = 32;
	}

	memcpy(no_fmt_string + i*32, cipher_text + offset, length_of_c1x);
	offset += length_of_c1x;
	*no_fmt_string_len += length_of_c1x;

	offset += 1;
    }
    
    return 0;
}
