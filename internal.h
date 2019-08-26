#ifndef INTERNAL_H
#define INTERNAL_H

/**
 *  \brief 去掉openssl中SM2加密结果中的格式信息
 *
 *  Detailed description
 *
 *  \param param
 *  \return return type
 */
int decode_cipher_text(const unsigned char* cipher_text, int cipher_text_len,
				   unsigned char* no_fmt_string, int* no_fmt_string_len);

/**
 *  \brief 将密文信息转换成openssl中识别的格式
 *
 *  Detailed description
 *
 *  \param param
 *  \return return type
 */
int encode_cipher_text(const char* cipher, int cipher_len, char* encoded_cipher, int* encoded_cipher_len);


#endif /* INTERNAL_H */
