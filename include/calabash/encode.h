#ifndef ENCODE_H
#define ENCODE_H

/**
 * @brief 将16进制的字符串转换为2进制字符序列
 * @details 将16进制的字符串转换为2进制字符序列,
 * 通常两个16进制字符转换成一个2进制字符,例如,"30"将转换成ASCII码为0x30的字符。
 * 
 * @param src 待转换的16进制的字符串
 * @param src_len 待转换的16进制的字符串的长度
 * @param dst 转换后的2进制字符序列
 * @param dst_len 转换后的2进制字符序列长度 
 * @return 成功返回0，否则表示失败
 */
int hex_to_bin(const char *src, int src_len, char *dst, int *dst_len);

/**
 * @brief 将16进制的字符串转换为2进制字符序列
 * @details 将16进制的字符串转换为2进制字符序列,
 * 通常两个16进制字符转换成一个2进制字符,例如,"30"将转换成ASCII码为0x30的字符。
 * 
 * @param src 待转换的16进制的字符串
 * @param src_len 待转换的16进制的字符串的长度
 * @param dst 转换后的2进制字符序列
 * @param dst_len 转换后的2进制字符序列长度 
 * @return 成功返回0，否则表示失败
 */
int cb_hex_to_bin(const char *src, int src_len, char *dst);

/**
 * @brief 将2进制的字符串转换为16进制字符序列
 * @details 将2进制的字符串转换为16进制字符序列,
 * 通常一个2进制字符转换成两个16进制字符,例如,ASCII码为0x30的字符将转换成"30"。
 * 
 * @param src 待转换的2进制的字符串
 * @param src_len 待转换的2进制的字符串的长度
 * @param dst 转换后的16进制字符序列
 * @param dst_len 转换后的16进制字符序列长度 
 * @return 成功返回0, 否则表示失败
 */
int bin_to_hex(const char *src, int src_len, char *dst, int *dst_len);

/**
 * @brief 将2进制的字符串转换为16进制字符序列
 * @details 将2进制的字符串转换为16进制字符序列,
 * 通常一个2进制字符转换成两个16进制字符,例如,ASCII码为0x30的字符将转换成"30"。
 * 
 * @param src 待转换的2进制的字符串
 * @param src_len 待转换的2进制的字符串的长度
 * @param dst 转换后的16进制字符序列
 * @param dst_len 转换后的16进制字符序列长度 
 * @return 成功返回0, 否则表示失败
 */
int cb_bin_to_hex(const char *src, int src_len, char *dst);

int base64_to_bin(const char *src, int src_len, char *dst);
int bin_to_base64(const char *src, int src_len, int nl_flag, char *dst);


#endif // !ENCODE_H