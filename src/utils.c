#include <string.h>
#include "calabash/utils.h"


static inline int _decode_der(const unsigned char* str, int str_len, unsigned char* out_str)
{
    int char_of_length = 0;
    int length_of_content = 0;
    int offset = 0;
    int out_len = 0;
    
    // 第一个字节必须是0x30
    if (str[0] != 0x30 ) return -1;

    // 计算后续长度
    if (str[1] > 0x80) {
	char_of_length = str[1] - 0x80;
	switch(char_of_length) {
	case 1:
	    length_of_content = str[2];
	    offset = 3;
	    break;
	case 2:
	    length_of_content = str[2]*256 + str[3];
	    offset = 4;
	    break;
	case 3:
	    length_of_content = str[2]*256*256 + str[3]*256 + str[4];
	    offset = 5;
	    break;
	}
		
    } else {
	length_of_content = str[1];
	offset = 2;
    }

    // 数据长度应该等于偏移加上后续内容长度
    if (length_of_content + offset != str_len) return -2;

    //  循环处理数据
    out_len = 0;
    while (offset < str_len) {
	// 需要跳过第一个TAG
	offset += 1;
	int len_of_next = *(str+offset);
	offset += 1;

	// 专门为openssl中的椭圆曲线，取出前导的0x00
	if (len_of_next == 0x21 && str[offset] == 0x0) {
	    offset += 1;
	    len_of_next -= 1;
	}

	memcpy(out_str + out_len, str + offset, len_of_next);

	offset += len_of_next;
	out_len += len_of_next;
    }
    
    return out_len;
}

int cb_ut_decode_ec_cipher_str(const unsigned char* str, int str_len, unsigned char* out_str)
{
    return _decode_der(str, str_len, out_str);
}

static inline int _int2bytes(unsigned int i, char* out)
{
    int ret = 0;
    
    int t = i / 0x80;
    switch(t) {
    case 0:
	out[0] = i;
	ret = 1;
	break;
    case 1:
	out[0] = 0x81;
	out[1] = i;
	ret = 2;
	break;
    }

    return ret;
}

int cb_ut_encode_ec_cipher_str(const unsigned char* str, int str_len, unsigned char* out_str)
{
    int r_len = 32;
    int s_len = 32;
    unsigned char buff[4096] = { 0x0 };
    int prefix_pad_len  = 0;
    int total_len = 0;

    // part 1 and part 2, part 3
    
    for(int i = 0; i < 3; i++) {
	if (((*(str + i*32)&0x80) == 0x80) && i < 2) {
	    prefix_pad_len = 1;
	}

	if (i < 2) {
	    buff[total_len] = 0x02;
	} else {
	    buff[total_len] = 0x04;
	}
	
	// 前面填0
	memcpy(buff + prefix_pad_len + 2 + total_len, str + i*32, 32);
	buff[total_len + 1] = 32 + prefix_pad_len;

	total_len += (32 + 2 + prefix_pad_len);
	prefix_pad_len = 0;
    }

    *(buff + total_len) = 0x04;
    total_len += 1;

    int offset = _int2bytes(str_len - 96, buff + total_len);
   
    memcpy(buff + total_len + offset, str + 96, str_len - 96);
    total_len += offset;
    total_len += (str_len - 96);

    offset = 0;
    out_str[0] = 0x30;
    offset += 1;
    
    offset += _int2bytes(total_len, out_str + 1);
    memcpy(out_str + offset, buff, total_len);
    total_len += offset;
    
    return total_len;
}

int cb_ut_decode_ec_sign_str(const unsigned char* str, int str_len, unsigned char* out_str)				
{
    return _decode_der(str, str_len, out_str);
}

int cb_ut_encode_ec_sign_str(const unsigned char* str, int str_len, unsigned char* out_str)
{
    int r_len = 32;
    int s_len = 32;
    unsigned char buff[36] = { 0x0 };
    int prefix_pad_len  = 0;
    int total_len = 0;

    for(int i = 0; i < str_len/32; i++) {
	if ((*(str + i*32)&0x80) == 0x80) {
	    prefix_pad_len = 1;
	}

	// 前面填0
	memcpy(buff + prefix_pad_len + 2, str + i*32, 32);
	buff[0] = 0x02;
	buff[1] = 32+prefix_pad_len;

	// 保留前面两个字节占位符
	memcpy(out_str + 2 + total_len, buff, 32+prefix_pad_len + 2);
	memset(buff, 0x0, sizeof(buff));

	total_len += (32 + 2 + prefix_pad_len);
	prefix_pad_len = 0;
    }

    out_str[0] = 0x30;
    out_str[1] = total_len;

    return total_len + 2;
}
