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
#include "api.h"
#include "ascon.h"
#include "crypto_hash.h"
#include "permutations.h"
#include "printstate.h"

#if !ASCON_INLINE_MODE
#undef forceinline
#define forceinline
#endif

#ifdef ASCON_HASH_BYTES

#if ASCON_HASH_BYTES == 32 && ASCON_HASH_ROUNDS == 12
#define IV(i) ASCON_HASH_IV##i
#elif ASCON_HASH_BYTES == 32 && ASCON_HASH_ROUNDS == 8
#define IV(i) ASCON_HASHA_IV##i
#elif ASCON_HASH_BYTES == 0 && ASCON_HASH_ROUNDS == 12
#define IV(i) ASCON_XOF_IV##i
#elif ASCON_HASH_BYTES == 0 && ASCON_HASH_ROUNDS == 8
#define IV(i) ASCON_XOFA_IV##i
#endif

forceinline void ascon_inithash(ascon_state_t* s) {
  /* initialize */
#ifdef ASCON_PRINT_STATE
  *s = (ascon_state_t){{IV(), 0, 0, 0, 0}};
  printstate("initial value", s);
  P(s, 12);
#else
  *s = (ascon_state_t){{IV(0), IV(1), IV(2), IV(3), IV(4)}};
#endif
  printstate("initialization", s);
}

forceinline void ascon_absorb(ascon_state_t* s, const uint8_t* in,
                              uint64_t inlen) {
  /* absorb full plaintext blocks */
  while (inlen >= ASCON_HASH_RATE) {
    s->x[0] ^= LOAD(in, 8);
    printstate("absorb plaintext", s);
    P(s, ASCON_HASH_ROUNDS);
    in += ASCON_HASH_RATE;
    inlen -= ASCON_HASH_RATE;
  }
  /* absorb final plaintext block */
  s->x[0] ^= LOADBYTES(in, inlen);
  s->x[0] ^= PAD(inlen);
  printstate("pad plaintext", s);
}

forceinline void ascon_squeeze(ascon_state_t* s, uint8_t* out,
                               uint64_t outlen) {
  /* squeeze full output blocks */
  P(s, 12);
  while (outlen > ASCON_HASH_RATE) {
    STORE(out, s->x[0], 8);
    printstate("squeeze output", s);
    P(s, ASCON_HASH_ROUNDS);
    out += ASCON_HASH_RATE;
    outlen -= ASCON_HASH_RATE;
  }
  /* squeeze final output block */
  STOREBYTES(out, s->x[0], outlen);
  printstate("squeeze output", s);
}

int ascon_xof(uint8_t* out, uint64_t outlen, const uint8_t* in,
              uint64_t inlen) {
  ascon_state_t s;
  printbytes("m", in, inlen);
  ascon_inithash(&s);
  ascon_absorb(&s, in, inlen);
  ascon_squeeze(&s, out, outlen);
  printbytes("h", out, outlen);
  return 0;
}

int crypto_hash(unsigned char* out, const unsigned char* in,
                unsigned long long inlen) {
  return ascon_xof(out, CRYPTO_BYTES, in, inlen);
}

#endif
int CryptHash(int digest_len_bits, const unsigned char *msg,
              unsigned long long msg_len_bits, unsigned char *digest)
{
    // 验证参数
    if (!msg || !digest || digest_len_bits <= 0) {
        return -1; // 错误码
    }
    
    // 检查输出长度是否匹配
    if (digest_len_bits != CRYPTO_BYTES * 8) {
        return -1; // 输出长度不匹配
    }
    
    // 将比特长度转换为字节长度
    unsigned long long msg_len_bytes = (msg_len_bits + 7) / 8;
    
    return crypto_hash(digest, msg, msg_len_bytes);
}