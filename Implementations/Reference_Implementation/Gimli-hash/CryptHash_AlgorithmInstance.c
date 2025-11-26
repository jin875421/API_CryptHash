/*
The software is provided by the Institute of Commercial Cryptography Standards
(ICCS), and is used for algorithm submissions in the Next-generation Commercial
Cryptographic Algorithms Program (NGCC).

ICCS doesn't represent or warrant that the operation of the software will be
uninterrupted or error-free in all cases. ICCS will take no responsibility for
the use of the software or the results thereof, if the software is used for any
other purposes.
*/

#include "CryptHash_AlgorithmInstance.h"
#include "gimli_hash.h"
#include <string.h>

int CryptHash(int digest_len_bits, const unsigned char *msg, 
              unsigned long long msg_len_bits, unsigned char *digest)
{
    // 将比特长度转换为字节长度
    unsigned long long msg_len_bytes = (msg_len_bits + 7) / 8;
    unsigned long long digest_len_bytes = digest_len_bits / 8;
    
    // 验证输出长度是否支持
    if (digest_len_bytes > 64) { 
        return -1; // 不支持的输出长度
    }
    
    // 处理非字节对齐的输入数据
    if (msg_len_bits % 8 != 0) {
        // 对于非字节对齐数据，需要创建对齐的副本
        unsigned char last_byte_mask = 0xFF << (8 - (msg_len_bits % 8));
        unsigned long long aligned_len = msg_len_bytes;
        unsigned char *aligned_msg = malloc(aligned_len);
        
        if (!aligned_msg) return -1;
        
        // 复制数据并处理最后一个字节
        memcpy(aligned_msg, msg, aligned_len);
        aligned_msg[aligned_len - 1] &= last_byte_mask;
        
        Gimli_hash(aligned_msg, aligned_len, digest, digest_len_bytes);
        free(aligned_msg);
    } else {
        // 字节对齐的情况直接处理
        Gimli_hash(msg, msg_len_bytes, digest, digest_len_bytes);
    }
    
    return 0;
}