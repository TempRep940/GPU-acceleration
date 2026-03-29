//AI generated test

#include "header/api.h"
#include "header/ascon.h"
#include "header/permutations.h"
#include "header/printstate.h"
#include "header/word.h"
#include "ascon_sup/dataGen.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <windows.h>

/* ============================================================
 * DEBUG HELPERS (ADDED ONLY)
 * ============================================================ */

__host__ __device__ __forceinline__
void debug_print_state_basic(const char *tag, const state_t *s)
{
  printf("[BASIC][%s]\n", tag);
  printf("x0 = %016llx\n", s->x0);
  printf("x1 = %016llx\n", s->x1);
  printf("x2 = %016llx\n", s->x2);
  printf("x3 = %016llx\n", s->x3);
  printf("x4 = %016llx\n", s->x4);
}

 __device__ __forceinline__
void debug_print_state_five(const char *tag, uint64_t s_x)
{
  uint64_t x0 = __shfl_sync(0x1F, s_x, 0);
  uint64_t x1 = __shfl_sync(0x1F, s_x, 1);
  uint64_t x2 = __shfl_sync(0x1F, s_x, 2);
  uint64_t x3 = __shfl_sync(0x1F, s_x, 3);
  uint64_t x4 = __shfl_sync(0x1F, s_x, 4);

  if (threadIdx.x == 0)
  {
    printf("[FIVE][%s]\n", tag);
    printf("x0 = %016llx\n", x0);
    printf("x1 = %016llx\n", x1);
    printf("x2 = %016llx\n", x2);
    printf("x3 = %016llx\n", x3);
    printf("x4 = %016llx\n", x4);
  }
}

/* ============================================================
 * BASIC GPU IMPLEMENTATION (UNCHANGED + DEBUG)
 * ============================================================ */

__host__ __device__ int crypto_aead_encrypt(
    unsigned char *c, unsigned long long *clen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec, const unsigned char *npub,
    const unsigned char *k)
{
  (void)nsec;
  *clen = mlen + CRYPTO_ABYTES;

  const uint64_t K0 = LOADBYTES(k, 8);
  const uint64_t K1 = LOADBYTES(k + 8, 8);
  const uint64_t N0 = LOADBYTES(npub, 8);
  const uint64_t N1 = LOADBYTES(npub + 8, 8);

  state_t s;
  s.x0 = ASCON_128_IV;
  s.x1 = K0;
  s.x2 = K1;
  s.x3 = N0;
  s.x4 = N1;

  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;

  debug_print_state_basic("after init", &s);

  if (adlen)
  {
    while (adlen >= ASCON_128_RATE)
    {
      s.x0 ^= LOADBYTES(ad, 8);
      P6(&s);
      ad += ASCON_128_RATE;
      adlen -= ASCON_128_RATE;
    }
    s.x0 ^= LOADBYTES(ad, adlen);
    s.x0 ^= PAD(adlen);
    P6(&s);
  }

  s.x4 ^= 1;
  debug_print_state_basic("after AD", &s);

  while (mlen >= ASCON_128_RATE)
  {
    s.x0 ^= LOADBYTES(m, 8);
    STOREBYTES(c, s.x0, 8);
    P6(&s);
    m += ASCON_128_RATE;
    c += ASCON_128_RATE;
    mlen -= ASCON_128_RATE;
  }

  s.x0 ^= LOADBYTES(m, mlen);
  STOREBYTES(c, s.x0, mlen);
  s.x0 ^= PAD(mlen);
  c += mlen;

  debug_print_state_basic("after plaintext", &s);

  s.x1 ^= K0;
  s.x2 ^= K1;
  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;

  debug_print_state_basic("after final", &s);

  STOREBYTES(c, s.x3, 8);
  STOREBYTES(c + 8, s.x4, 8);

  return 0;
}

/* ============================================================
 * FINE-GRAINED (5 THREADS) IMPLEMENTATION + DEBUG
 * ============================================================ */

__device__ static __forceinline__ void ROUND_FIVE(uint64_t *s_x, uint8_t C)
{
  if (threadIdx.x == 2)
    *s_x ^= C;

  {
    uint64_t temp = __shfl_sync(0x1F, *s_x, 4);
    if (threadIdx.x == 0)
      *s_x ^= temp;

    temp = __shfl_up_sync(0x1F, *s_x, 1);
    if (threadIdx.x == 2 || threadIdx.x == 4)
      *s_x ^= temp;
  }

  {
    uint64_t temp1 = __shfl_sync(0x1F, *s_x, (threadIdx.x + 1) % 5);
    uint64_t temp2 = __shfl_sync(0x1F, *s_x, (threadIdx.x + 2) % 5);
    *s_x = *s_x ^ ((~temp1) & temp2);
  }

  {
    uint64_t temp = __shfl_sync(0x1F, *s_x, (threadIdx.x + 4) % 5);
    if (threadIdx.x == 1 || threadIdx.x == 0 || threadIdx.x == 3)
      *s_x ^= temp;
  }

  if (threadIdx.x == 2)
    *s_x = ~*s_x;

  int t1 = 0, t2 = 0;
  switch (threadIdx.x)
  {
  case 0: t1 = 19; t2 = 28; break;
  case 1: t1 = 61; t2 = 39; break;
  case 2: t1 = 1;  t2 = 6;  break;
  case 3: t1 = 10; t2 = 17; break;
  case 4: t1 = 7;  t2 = 41; break;
  }
  *s_x = *s_x ^ ROR(*s_x, t1) ^ ROR(*s_x, t2);
}

__device__ static __forceinline__ void P12_FIVE(uint64_t *s_x)
{
  ROUND_FIVE(s_x, 0xf0); ROUND_FIVE(s_x, 0xe1);
  ROUND_FIVE(s_x, 0xd2); ROUND_FIVE(s_x, 0xc3);
  ROUND_FIVE(s_x, 0xb4); ROUND_FIVE(s_x, 0xa5);
  ROUND_FIVE(s_x, 0x96); ROUND_FIVE(s_x, 0x87);
  ROUND_FIVE(s_x, 0x78); ROUND_FIVE(s_x, 0x69);
  ROUND_FIVE(s_x, 0x5a); ROUND_FIVE(s_x, 0x4b);
}

__device__ static __forceinline__ void P6_FIVE(uint64_t *s_x)
{
  ROUND_FIVE(s_x, 0x96); ROUND_FIVE(s_x, 0x87);
  ROUND_FIVE(s_x, 0x78); ROUND_FIVE(s_x, 0x69);
  ROUND_FIVE(s_x, 0x5a); ROUND_FIVE(s_x, 0x4b);
}

__global__ void ascon_encrypt_one_in_five(
    char *plaintext_d, char *ad_d,
    char *key_and_nonce, char *ciphertext_d)
{
  int tid = threadIdx.x + blockIdx.x * blockDim.x;
  if (tid >= 5) return;

  uint64_t kn = 0;
  if (tid % 5 != 0)
    kn = LOADBYTES((const uint8_t *)(key_and_nonce + (tid - 1) * 8), 8);

  uint64_t s_x = (tid % 5 != 0) ? kn : ASCON_128_IV;

  P12_FIVE(&s_x);

  {
    uint64_t temp = __shfl_up_sync(0x1F, kn, 2);
    if (threadIdx.x == 3 || threadIdx.x == 4)
      s_x ^= temp;
  }

  debug_print_state_five("after init", s_x);

  unsigned long long adlen = 16;
  if (adlen)
  {
    while (adlen >= 8)
    {
      if (threadIdx.x == 0)
        s_x ^= LOADBYTES((const uint8_t *)ad_d, 8);
      P6_FIVE(&s_x);
      ad_d += 8;
      adlen -= 8;
    }
    if (threadIdx.x == 0)
    {
      s_x ^= LOADBYTES((const uint8_t *)ad_d, adlen);
      s_x ^= PAD(adlen);
    }
    P6_FIVE(&s_x);
  }

  if (threadIdx.x == 4)
    s_x ^= 1;

  debug_print_state_five("after AD", s_x);

  unsigned long long mlen = 16;
  while (mlen >= 8)
  {
    if (threadIdx.x == 0)
    {
      s_x ^= LOADBYTES((const uint8_t *)plaintext_d, 8);
      STOREBYTES((uint8_t *)ciphertext_d, s_x, 8);
    }
    P6_FIVE(&s_x);
    plaintext_d += 8;
    ciphertext_d += 8;
    mlen -= 8;
  }

  if (threadIdx.x == 0)
  {
    s_x ^= LOADBYTES((const uint8_t *)plaintext_d, mlen);
    STOREBYTES((uint8_t *)ciphertext_d, s_x, mlen);
    s_x ^= PAD(mlen);
  }

  debug_print_state_five("after plaintext", s_x);

  if (threadIdx.x == 1 || threadIdx.x == 2)
    s_x ^= kn;

  P12_FIVE(&s_x);

  {
    uint64_t temp = __shfl_up_sync(0x1F, kn, 2);
    if (threadIdx.x == 3 || threadIdx.x == 4)
      s_x ^= temp;
  }

  debug_print_state_five("after final", s_x);

  if (threadIdx.x == 3)
    STOREBYTES((uint8_t *)ciphertext_d, s_x, 8);
  if (threadIdx.x == 4)
    STOREBYTES((uint8_t *)ciphertext_d + 8, s_x, 8);
}

int main(int argc, char const *argv[]){
    /* Key (16 bytes for ASCON-128) */
    unsigned char key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };

    /* Nonce (16 bytes) */
    unsigned char nonce[16] = {
        0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,
        0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF
    };

    /* Plaintext message */
    const unsigned char plaintext[] = "1234123412341234";
    
    /* Associated Data (authenticated but not encrypted) */
    const unsigned char ad[] = "1234123412341234";

    unsigned long long pt_len = 16;
    unsigned long long ad_len = 16;

    /* Allocate buffer for ciphertext (plaintext + 16 bytes tag) */
    unsigned char *ciphertext = (unsigned char *)malloc(pt_len + 16);
    unsigned long long ct_len = 0;
    printf("============ Basic ASCON-128 Encryption ============\n\n");

    /* ENCRYPT */
    int ret = crypto_aead_encrypt(
        ciphertext, &ct_len,
        plaintext, pt_len,
        ad, ad_len,
        NULL,           /* nsec (not used) */
        nonce,
        key
    );

    printf("============ GPU ASCON-128 Encryption ============\n\n");

    char *key_and_nonce_h, *key_and_nonce_d;
    key_and_nonce_h = (char *)malloc(sizeof(char) * 32);
    cudaMalloc((void **)&key_and_nonce_d, sizeof(char) * 32);

  for (int i = 0; i < 16; i++)
  {
    key_and_nonce_h[i] = key[i];
    
    key_and_nonce_h[i+16] = nonce[i];
  }
  cudaMemcpy(key_and_nonce_d, key_and_nonce_h, sizeof(char) * 32, cudaMemcpyHostToDevice);

  char * plaintext_d, * ad_d, *ciphertext_d;

  cudaMalloc((void **)&plaintext_d, sizeof(char) * 16 * 1);
  cudaMalloc((void **)&ad_d, sizeof(char) * 16 * 1);
  cudaMalloc((void **)&ciphertext_d, sizeof(char) * (16 + 16) * 1);

  cudaMemcpy(plaintext_d, plaintext, sizeof(char) * 16 * 1, cudaMemcpyHostToDevice);
  cudaMemcpy(ad_d, ad, sizeof(char) * 16 * 1, cudaMemcpyHostToDevice);

  ascon_encrypt_one_in_five<<<1, 5>>>(plaintext_d, ad_d, key_and_nonce_d, ciphertext_d);



}