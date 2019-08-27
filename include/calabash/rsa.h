#ifndef RSA_H
#define RSA_H

/**
 * @brief 从PEM文件读取RSA密钥
 * @details 从PEM文件读取RSA密钥，支持公钥和私钥
 * 
 * @param pem_file PEM文件
 * @param puk 从PEM文件中获取的密钥，密钥格式是DER格式
 * @return 返回密钥长度，负数表示失败
 */
int rsa_read_key_from_pem_file(const char* pem_file, char* puk);

/**
 * @brief 从PEM串读取RSA密钥
 * @details 从PEM串读取RSA密钥，支持公钥和私钥
 * 
 * @param pem_file PEM串，必须是PKCS#1或者PKCS#8的格式
 * @param puk 从PEM串中获取的密钥，密钥格式是DER格式
 * @return 返回密钥长度，负数表示失败
 */
int rsa_read_key_from_pem_str(const char* pem_str, int pem_str_len, char* puk);


/**
 * @brief 把DER格式的公钥由PKCS8转换成PKCS1
 * @details 把DER格式的公钥由PKCS8转换成PKCS1
 * 
 * @param pcks8_key PKCS#8格式的公钥
 * @param pcks8_key_len PKCS#8格式的公钥长度
 * @param pcks1_key PKCS#1格式的公钥
 * @return 返回密钥长度，负数表示失败
 */
int rsa_transfer_key_pkcs8_to_pkcs1(const char* pcks8_key, int pcks8_key_len, char* pcks1_key);

/**
 * @brief 生成RSA密钥对
 * @details 生成RSA密钥对
 * 
 * @param bits RSA密钥长度，必须是8的倍数，建议1024以上
 * @param pvk 生成的RSA私钥
 * @param pvk_len 生成的RSA私钥长度
 * @param puk 生成的RSA公钥
 * @param puk_len 生成的RSA公钥长度
 * @return 成功返回0，否则表示失败
 */
int rsa_generate_key(int bits, char* pvk, int* pvk_len, char* puk, int * puk_len);

/**
 * @brief 把RSA公钥转换成PKCS#1的PEM字符串
 * @details 把RSA公钥转换成PCKS#1的PEM字符串
 * 
 * @param puk 待转换的RSA公钥
 * @param puk_len 待转换的RSA公钥长度
 * @param pem_str 转换后的RSA公钥
 * @return 成功返回转换后的RSA公钥的长度，负数表示失败
 */
int rsa_dump_puk_to_pem_str(const char* puk, int puk_len, char* pem_str);


/**
 * @brief 把RSA公钥转换成PKCS#8的PEM字符串
 * @details 把RSA公钥转换成PCKS#8的PEM字符串
 * 
 * @param puk 待转换的RSA公钥
 * @param puk_len 待转换的RSA公钥长度
 * @param pem_str 转换后的RSA公钥
 * @return 成功返回转换后的RSA公钥的长度，负数表示失败
 */
int rsa_dump_puk_to_pcks8_pem_str(const char* puk, int puk_len, char* pem_str);

/**
 * @brief 把RSA私钥转换成PKCS#1的PEM字符串
 * @details 把RSA私钥转换成PCKS#1的PEM字符串
 * 
 * @param puk 待转换的RSA私钥
 * @param puk_len 待转换的RSA私钥长度
 * @param pem_str 转换后的RSA私钥
 * @return 成功返回转换后的RSA私钥的长度，负数表示失败
 */
int rsa_dump_pvk_to_pem_str(const char* pvk, int pvk_len, char* pem_str);

/**
 * @brief 把RSA私钥转换成PKCS#8的PEM字符串
 * @details 把RSA私钥转换成PCKS#8的PEM字符串
 * 
 * @param puk 待转换的RSA私钥
 * @param puk_len 待转换的RSA私钥长度
 * @param pem_str 转换后的RSA私钥
 * @return 成功返回转换后的RSA私钥的长度，负数表示失败
 */
int rsa_dump_pvk_to_pkcs8_pem_str(const char* pvk, int pvk_len, const char* password, char* pem_str);


/**
 * @brief 把RSA公钥转换保存为PKCS#1的PEM文件
 * @details 把RSA公钥转换保存成PCKS#1的PEM文件
 * 
 * @param puk 待转换的RSA公钥
 * @param puk_len 待转换的RSA公钥长度
 * @param file_name PEM文件
 * @return 成功返回PEM文件的长度，负数表示失败
 */
int rsa_dump_puk_to_pem_file(const char* puk, int puk_len, char* file_name);

/**
 * @brief 把RSA公钥转换保存为PKCS#8的PEM文件
 * @details 把RSA公钥转换保存成PCKS#8的PEM文件
 * 
 * @param puk 待转换的RSA公钥
 * @param puk_len 待转换的RSA公钥长度
 * @param file_name PEM文件
 * @return 成功返回PEM文件的长度，负数表示失败
 */
int rsa_dump_puk_to_pcks8_pem_file(const char* puk, int puk_len, char* file_name);


/**
 * @brief 把RSA私钥转换保存为PKCS#1的PEM文件
 * @details 把RSA私钥转换保存成PCKS#1的PEM文件
 * 
 * @param pvk 待转换的RSA私钥
 * @param pvk_len 待转换的RSA私钥长度
 * @param file_name PEM文件
 * @return 成功返回PEM文件的长度，负数表示失败
 */
int rsa_dump_pvk_to_pem_file(const char* pvk, int pvk_len, const char* password, char* file_name);

/**
 * @brief 把RSA私钥转换保存为PKCS#8的PEM文件
 * @details 把RSA私钥转换保存成PCKS#8的PEM文件
 * 
 * @param pvk 待转换的RSA私钥
 * @param pvk_len 待转换的RSA私钥长度
 * @param file_name PEM文件
 * @return 成功返回PEM文件的长度，负数表示失败
 */
int rsa_dump_pvk_to_pkcs8_pem_file(const char* pvk, int pvk_len, const char* password, char* file_name);

/**
 * @brief 使用RSA公钥加密数据
 * @details 使用RSA公钥加密数据
 * 
 * @param puk RSA公钥
 * @param puk_len RSA公钥长度
 * @param plain 待加密的明文
 * @param plain_len 待加密的明文长度
 * @param cipher 加密后的密文
 * @return 成功返回加密后密文的长度，负数表示失败
 */
int rsa_encrypt(const char* puk, int puk_len, const char* plain, int plain_len, char* cipher);

/**
 * @brief 使用RSA私钥解密数据
 * @details 使用RSA私钥解密数据
 * 
 * @param pvk RSA私钥
 * @param pvk_len RSA私钥长度
 * @param cipher 待解密的明文
 * @param cipher_len 待解密的密文长度
 * @param plain 解密后的明文
 * @return 成功返回解密后明文的长度，负数表示失败
 */
int rsa_decrypt(const char* pvk, int pvk_len, const char* cipher, int cipher_len, char* plain);

/**
 * @brief 使用RSA私钥对数据进行签名
 * @details 使用RSA私钥对数据进行签名
 * 
 * @param pvk RSA私钥
 * @param pvk_len RSA私钥长度
 * @param msg 待签名的数据
 * @param msg_len 待签名的数据长度
 * @param digest_algo 摘要算法
 * @param sign 签名值
 * @return 成功返回签名值的长度，负数表示失败
 */
int rsa_sign(const char* pvk, int pvk_len, const char* msg, int msg_len, int digest_algo, char* sign);

/**
 * @brief 使用RSA公钥对签名进行验证
 * @details 使用RSA公钥对签名进行验证
 * 
 * @param puk RSA公钥
 * @param puk_len RSA公钥长度
 * @param msg 待验证的数据
 * @param msg_len 待验证的数据长度
 * @param digest_algo 摘要算法
 * @param sign 待验证的签名
 * @param sign_len 待验证的签名长度
 * @return 成功返回0，否则表示失败
 */
int rsa_verify(const char* puk, int puk_len, const char* msg, int msg_len, int digest_algo, const char* sign, int sign_len);

#endif // !RSA_H