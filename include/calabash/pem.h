#ifndef PEM_H
#define PEM_H

/**
 *  @brief 从pem文件读取SM2私钥
 *  @details 从pem文件读取SM2私钥
 *  
 *  @param pemfile pem文件路径
 *  @param pvk 从pem文件中返回的sm2私钥
 *  @param pvk_len 从pem文件中返回的sm2私钥长度，固定为32
 *  @return 成功返回0, 否则表示失败
 */
int sm2_read_pvk_from_pemfile(const char *pemfile, char *pvk, int *pvk_len);

/**
 *  @brief 从pem串读取SM2私钥
 *  @details 从pem串读取SM2私钥
 *  
 *  @param pem_str pem串
 *  @param pem_str_len pem串的长度
 *  @param pvk 从pem文件中返回的sm2私钥
 *  @param pvk_len 从pem文件中返回的sm2私钥长度，固定为32
 *  @return 成功返回0, 否则表示失败
 */
int sm2_read_pvk_from_pem_str(const char *pem_str, int pem_str_len, char *pvk, int *pvk_len);

/**
 *  @brief 从pem文件读取SM2公钥
 *  @details 从pem文件读取SM2公钥
 *  
 *  @param pemfile pem文件路径
 *  @param pvk 从pem文件中返回的sm2公钥
 *  @param pvk_len 从pem文件中返回的sm2公钥长度，通常为64字节
 *  @return 成功返回0, 否则表示失败
 */
int sm2_read_puk_from_pemfile(const char *pemfile, char *puk, int *puk_len);

/**
 *  @brief 从pem文件读取SM2公钥
 *  @details 从pem文件读取SM2公钥
 *  
 *  @param pem_str pem串
 *  @param pem_str_len pem串的长度
 *  @param puk 从pem文件中返回的sm2公钥
 *  @param puk_len 从pem文件中返回的sm2公钥长度，通常为64字节
 *  @return 成功返回0, 否则表示失败
 */
int sm2_read_puk_from_pem_str(const char *pem_str, int pem_str_len, char *puk, int *puk_len);


#endif // !PEM_H