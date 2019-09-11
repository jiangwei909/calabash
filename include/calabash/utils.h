#ifndef UTILS_H
#define UTILS_H

#define ECHO_COLOR_NONE         "\033[0;0m"
#define ECHO_COLOR_GREEN        "\033[0;32m"

#ifdef DEBUG
#define cb_debug(fmt, args...)     \
          printf(ECHO_COLOR_GREEN"Debug: " fmt "(file: %s, func: %s, line: %d)\n"ECHO_COLOR_NONE, ##args, __FILE__, __func__, __LINE__);
#else
#define cb_debug(fmt, args...)     
#endif

/**
 *  \brief 去掉openssl中SM2加密结果中的格式信息
 *
 *  Detailed description
 *
 *  \param param
 *  \return return type
 */
int cb_ut_decode_ec_sign_str(const unsigned char* str, int str_len, unsigned char* out_str);

/**
 *  \brief 将密文信息转换成openssl中识别的格式
 *
 *  Detailed description
 *
 *  \param param
 *  \return return type
 */
// int encode_cipher_text(const char* cipher, int cipher_len, char* encoded_cipher, int* encoded_cipher_len);
int cb_ut_encode_ec_sign_str(const unsigned char* str, int str_len, unsigned char* out_str);

int cb_ut_decode_ec_cipher_str(const unsigned char* str, int str_len, unsigned char* out_str);
int cb_ut_encode_ec_cipher_str(const unsigned char* str, int str_len, unsigned char* out_str);
#endif /* UTILS_H */
