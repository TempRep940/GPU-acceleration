#include "header/api.h"
#include "header/ascon.h"
/*
#include "header/crypto_aead.h"
*/
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
 * FROM: encrypt.c
 * ============================================================ */

__host__ __device__ int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
                                            const unsigned char *m, unsigned long long mlen,
                                            const unsigned char *ad, unsigned long long adlen,
                                            const unsigned char *nsec, const unsigned char *npub,
                                            const unsigned char *k)
{
  (void)nsec;

  /* set ciphertext size */
  *clen = mlen + CRYPTO_ABYTES;

  /* load key and nonce */
  const uint64_t K0 = LOADBYTES(k, 8);
  const uint64_t K1 = LOADBYTES(k + 8, 8);
  const uint64_t N0 = LOADBYTES(npub, 8);
  const uint64_t N1 = LOADBYTES(npub + 8, 8);

  /* initialize */
  state_t s;
  s.x0 = ASCON_128_IV;
  s.x1 = K0;
  s.x2 = K1;
  s.x3 = N0;
  s.x4 = N1;
  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;
  // printstate("initialization", &s);

  if (adlen)
  {
    /* full associated data blocks */
    while (adlen >= ASCON_128_RATE)
    {
      s.x0 ^= LOADBYTES(ad, 8);
      P6(&s);
      ad += ASCON_128_RATE;
      adlen -= ASCON_128_RATE;
    }
    /* final associated data block */
    s.x0 ^= LOADBYTES(ad, adlen);
    s.x0 ^= PAD(adlen);
    P6(&s);
  }
  /* domain separation */
  s.x4 ^= 1;
  // printstate("process associated data", &s);

  /* full plaintext blocks */
  while (mlen >= ASCON_128_RATE)
  {
    s.x0 ^= LOADBYTES(m, 8);
    STOREBYTES(c, s.x0, 8);
    P6(&s);
    m += ASCON_128_RATE;
    c += ASCON_128_RATE;
    mlen -= ASCON_128_RATE;
  }
  /* final plaintext block */
  s.x0 ^= LOADBYTES(m, mlen);
  STOREBYTES(c, s.x0, mlen);
  s.x0 ^= PAD(mlen);
  c += mlen;
  // printstate("process plaintext", &s);

  /* finalize */
  s.x1 ^= K0;
  s.x2 ^= K1;
  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;
  // printstate("finalization", &s);

  /* set tag */
  STOREBYTES(c, s.x3, 8);
  STOREBYTES(c + 8, s.x4, 8);

  return 0;
}

/* ============================================================
 * FROM: decrypt.c
 * ============================================================ */

__host__ __device__ int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
                                            unsigned char *nsec, const unsigned char *c,
                                            unsigned long long clen, const unsigned char *ad,
                                            unsigned long long adlen, const unsigned char *npub,
                                            const unsigned char *k)
{
  (void)nsec;

  if (clen < CRYPTO_ABYTES)
    return -1;

  /* set plaintext size */
  *mlen = clen - CRYPTO_ABYTES;

  /* load key and nonce */
  const uint64_t K0 = LOADBYTES(k, 8);
  const uint64_t K1 = LOADBYTES(k + 8, 8);
  const uint64_t N0 = LOADBYTES(npub, 8);
  const uint64_t N1 = LOADBYTES(npub + 8, 8);

  /* initialize */
  state_t s;
  s.x0 = ASCON_128_IV;
  s.x1 = K0;
  s.x2 = K1;
  s.x3 = N0;
  s.x4 = N1;
  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;
  // printstate("initialization", &s);

  if (adlen)
  {
    /* full associated data blocks */
    while (adlen >= ASCON_128_RATE)
    {
      s.x0 ^= LOADBYTES(ad, 8);
      P6(&s);
      ad += ASCON_128_RATE;
      adlen -= ASCON_128_RATE;
    }
    /* final associated data block */
    s.x0 ^= LOADBYTES(ad, adlen);
    s.x0 ^= PAD(adlen);
    P6(&s);
  }
  /* domain separation */
  s.x4 ^= 1;
  // printstate("process associated data", &s);

  /* full ciphertext blocks */
  clen -= CRYPTO_ABYTES;
  while (clen >= ASCON_128_RATE)
  {
    uint64_t c0 = LOADBYTES(c, 8);
    STOREBYTES(m, s.x0 ^ c0, 8);
    s.x0 = c0;
    P6(&s);
    m += ASCON_128_RATE;
    c += ASCON_128_RATE;
    clen -= ASCON_128_RATE;
  }
  /* final ciphertext block */
  uint64_t c0 = LOADBYTES(c, clen);
  STOREBYTES(m, s.x0 ^ c0, clen);
  s.x0 = CLEARBYTES(s.x0, clen);
  s.x0 |= c0;
  s.x0 ^= PAD(clen);
  c += clen;
  // printstate("process ciphertext", &s);

  /* finalize */
  s.x1 ^= K0;
  s.x2 ^= K1;
  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;
  // printstate("finalization", &s);

  /* set tag */
  uint8_t t[16];
  STOREBYTES(t, s.x3, 8);
  STOREBYTES(t + 8, s.x4, 8);

  /* verify tag (should be constant time, check compiler output) */
  int result = 0;
  for (int i = 0; i < CRYPTO_ABYTES; ++i)
    result |= c[i] ^ t[i];
  result = (((result - 1) >> 8) & 1) - 1;

  return result;
}

/*
Set the following three prameters as fixed length for testing:
plaintext: 16 Bytes
ciphertext: 16 Bytes + 16 Bytes tag
associated data: 16 Bytes

Set nonce and key as constant for testing:
nonce: 16 Bytes
key: 16 Bytes

*/
//=====================basic developeent=====================↓//

// for palintext and associated data
#define LENGTH 16
// How many times of encryption/decryption do you want to perform
#define SIZE 1

#define BLOCK_SIZE 1

__constant__ char nonce[16];

__constant__ char key[16];

__global__ void ascon_encrypt_device(char *plaintext_d, char *ad_d, char *ciphertext_d)
{
  // a dummy variable to hold the length of ciphertext
  // actually it is LENGTH + 16 Bytes tag
  unsigned long long clen;
  int tid = threadIdx.x + blockIdx.x * blockDim.x;

  char *plaintext = LENGTH * tid + plaintext_d;
  char *ad = LENGTH * tid + ad_d;
  char *ciphertext = (LENGTH + 16) * tid + ciphertext_d;

  crypto_aead_encrypt((unsigned char *)ciphertext, &clen,
                      (const unsigned char *)plaintext, LENGTH,
                      (const unsigned char *)ad, LENGTH,
                      NULL, (const unsigned char *)nonce,
                      (const unsigned char *)key);
}
__global__ void ascon_decrypt_device(char *ciphertext_d, char *ad_d, char *decryptedtext_d)
{
  // a dummy variable to hold the length of plaintext
  // actually it is LENGTH Bytes
  unsigned long long mlen;
  int tid = threadIdx.x + blockIdx.x * blockDim.x;

  char *ciphertext = (LENGTH + 16) * tid + ciphertext_d;
  char *ad = LENGTH * tid + ad_d;
  char *decryptedtext = LENGTH * tid + decryptedtext_d;

  crypto_aead_decrypt((unsigned char *)decryptedtext, &mlen,
                      NULL, (const unsigned char *)ciphertext,
                      LENGTH + 16,
                      (const unsigned char *)ad, LENGTH,
                      (const unsigned char *)nonce,
                      (const unsigned char *)key);
}

__global__ void warmup_kernel()
{
  // do nothing
  return;
}

//=====================fine-grained developeent=====================↓//

// Use 5 threads to do one encryption/decryption
// each thread holds a value in the structure state_t (x0~x4 )
__device__ static __forceinline__ void ROUND_FIVE(uint64_t *s_x, uint8_t C)
{
  /* addition of round constant */
  if (threadIdx.x == 2)
    *s_x ^= C;
  /* substitution layer */
  {
    uint64_t temp = 0;

    // thead 3 doesn't participate

    // 1000 0: only thread 0 gets the value
    temp = __shfl_sync(0x1F, *s_x, 4);
    if (threadIdx.x == 0) // Run thread 0 first because of data dependency
    {

      *s_x ^= temp;
    }

    // 0010 1:only thread 2 and thread 4 get the value
    temp = __shfl_up_sync(0x1F, *s_x, 1);
    if (threadIdx.x == 2 || threadIdx.x == 4)
    {

      *s_x ^= temp;
    }
  }
  /* start of keccak s-box */
  {
    uint64_t temp1 = 0;
    uint64_t temp2 = 0;

    temp1 = __shfl_sync(0x1F, *s_x, (threadIdx.x + 1) % 5);
    temp2 = __shfl_sync(0x1F, *s_x, (threadIdx.x + 2) % 5);

    *s_x = *s_x ^ ((~temp1) & temp2);
  }
  /* end of keccak s-box */

  // only thread 0,1,3 participate
  {
    uint64_t temp = 0;

    temp = __shfl_sync(0x1F, *s_x, (threadIdx.x + 4) % 5);
    if (threadIdx.x == 1)
      *s_x ^= temp;

    if (threadIdx.x == 0 || threadIdx.x == 3)
    {
      *s_x ^= temp;
    }
  }

  if (threadIdx.x == 2)
  {
    *s_x = ~*s_x;
  }

  /* linear diffusion layer */
  {
    int temp1 = 0;
    int temp2 = 0;

    switch (threadIdx.x)
    {
    case 0:
      temp1 = 19;
      temp2 = 28;
      break;
    case 1:
      temp1 = 61;
      temp2 = 39;
      break;
    case 2:
      temp1 = 1;
      temp2 = 6;
      break;
    case 3:
      temp1 = 10;
      temp2 = 17;
      break;
    case 4:
      temp1 = 7;
      temp2 = 41;
      break;
    }
    *s_x = *s_x ^ ROR(*s_x, temp1) ^ ROR(*s_x, temp2);
  }
}

__device__ static __forceinline__ void P12_FIVE(uint64_t *s_x)
{
  ROUND_FIVE(s_x, 0xf0);
  ROUND_FIVE(s_x, 0xe1);
  ROUND_FIVE(s_x, 0xd2);
  ROUND_FIVE(s_x, 0xc3);
  ROUND_FIVE(s_x, 0xb4);
  ROUND_FIVE(s_x, 0xa5);
  ROUND_FIVE(s_x, 0x96);
  ROUND_FIVE(s_x, 0x87);
  ROUND_FIVE(s_x, 0x78);
  ROUND_FIVE(s_x, 0x69);
  ROUND_FIVE(s_x, 0x5a);
  ROUND_FIVE(s_x, 0x4b);
}
__device__ static __forceinline__ void P6_FIVE(uint64_t *s_x)
{
  ROUND_FIVE(s_x, 0x96);
  ROUND_FIVE(s_x, 0x87);
  ROUND_FIVE(s_x, 0x78);
  ROUND_FIVE(s_x, 0x69);
  ROUND_FIVE(s_x, 0x5a);
  ROUND_FIVE(s_x, 0x4b);
}
__global__ void ascon_encrypt_one_in_five(char *plaintext_d, char *ad_d, char *key_and_nonce, char *ciphertext_d)
{

  int tid = threadIdx.x + blockIdx.x * blockDim.x;
  // only 5 thread are needed
  if (tid >= 5)
  {
    return;
  }

  char *kn_offset;
  uint64_t kn = 0;

  if (tid % 5 != 0)
  {
    kn_offset = key_and_nonce + (tid - 1) * 8;
    kn = LOADBYTES((const uint8_t *)kn_offset, 8);
  }
  /*
  kn:
  thread 0-> 0 do nothing
  thread 1-> K0
  thread 2-> K1
  thread 3-> N0
  thread 4-> N1
  */

  /* initialize */
  // state_t s;
  uint64_t s_x = (tid % 5 != 0) ? kn : ASCON_128_IV;
  /*
  s_x
  thread 0-> s.x0
  thread 1-> s.x1
  thread 2-> s.x2
  thread 3-> s.x3
  thread 4-> s.x4
  */

  // P12(&s);
  P12_FIVE(&s_x);

  {
    uint64_t temp = __shfl_up_sync(0x1F, kn, 2);
    if (threadIdx.x == 3 || threadIdx.x == 4)
      s_x ^= temp;
  }

  {
    unsigned long long adlen = LENGTH;
    /* full associated data blocks */
    if (adlen)
    {
      while (adlen >= ASCON_128_RATE)
      {
        if (threadIdx.x == 0)
          s_x ^= LOADBYTES((const uint8_t *)ad_d, 8);
        // P6
        P6_FIVE(&s_x);

        ad_d += ASCON_128_RATE;
        adlen -= ASCON_128_RATE;
      }
      /* final associated data block */
      if (threadIdx.x == 0)
      {
        s_x ^= LOADBYTES((const uint8_t *)ad_d, adlen);
        s_x ^= PAD(adlen);
      }
      // P6
      P6_FIVE(&s_x);
    }
  }
  /* domain separation */
  if (threadIdx.x == 4)
    s_x ^= 1;

  /* full plaintext blocks */
  {
    unsigned long long mlen = LENGTH;
    while (mlen >= ASCON_128_RATE)
    {
      if (threadIdx.x == 0)
      {
        s_x ^= LOADBYTES((const uint8_t *)plaintext_d, 8);
        STOREBYTES((uint8_t *)ciphertext_d, s_x, 8);
      }
      // P6
      P6_FIVE(&s_x);
      plaintext_d += ASCON_128_RATE;
      ciphertext_d += ASCON_128_RATE;
      mlen -= ASCON_128_RATE;
    }

    /* final plaintext block */
    if (threadIdx.x == 0)
    {
      s_x ^= LOADBYTES((const uint8_t *)plaintext_d, mlen);
      STOREBYTES((uint8_t *)ciphertext_d, s_x, mlen);
      s_x ^= PAD(mlen);
      ciphertext_d += mlen;
    }

    // NB! Other threads have different pointer for ciphertext_d
    // Broadcast the pointer of thread 0 to other threads
    // warp shuffle can not deal with pointer
    // So we cast the pointer to unsigned long long first
    ciphertext_d = (char *)__shfl_sync(0x1F, (unsigned long long)ciphertext_d, 0);
  }

  /* finalize */
  if (threadIdx.x == 1 || threadIdx.x == 2)
  {
    s_x ^= kn;
  }

  // P12
  P12_FIVE(&s_x);
  {
    // NB! Do not put warp shuffle inside the if condition
    // may cause error?
    uint64_t temp = __shfl_up_sync(0x1F, kn, 2);
    if (threadIdx.x == 3 || threadIdx.x == 4)
      s_x ^= temp;
  }
  /* set tag */
  if (threadIdx.x == 3)
    STOREBYTES((uint8_t *)ciphertext_d, s_x, 8);
  if (threadIdx.x == 4)
    STOREBYTES((uint8_t *)ciphertext_d + 8, s_x, 8);
}

__global__ void ascon_decrypt_one_in_five(char *ciphertext_d, char *ad_d, char *key_and_nonce, char *decryptedtext_d, char *flag_d)
{
  // Assume that the input ciphertext is legal
  // if (clen < CRYPTO_ABYTES) return -1;

  /* set plaintext size */
  //*mlen = clen - CRYPTO_ABYTES;
  // the size is controlled by LENGTH

  int tid = threadIdx.x + blockIdx.x * blockDim.x;
  // only 5 thread are needed
  if (tid >= 5)
  {
    return;
  }

  /* load key and nonce */
  char *kn_offset;
  uint64_t kn = 0;

  if (tid % 5 != 0)
  {
    kn_offset = key_and_nonce + (tid - 1) * 8;
    kn = LOADBYTES((const uint8_t *)kn_offset, 8);
  }
  /*
  kn:
  thread 0-> 0 do nothing
  thread 1-> K0
  thread 2-> K1
  thread 3-> N0
  thread 4-> N1
  */

  /* initialize */
  // state_t s;
  uint64_t s_x = (tid % 5 != 0) ? kn : ASCON_128_IV;
  /*
  s_xE
  thread 0-> s.x0
  thread 1-> s.x1
  thread 2-> s.x2
  thread 3-> s.x3
  thread 4-> s.x4
  */
  P12_FIVE(&s_x);

  {
    uint64_t temp = __shfl_up_sync(0x1F, kn, 2);
    if (threadIdx.x == 3 || threadIdx.x == 4)
      s_x ^= temp;
  }

  {
    unsigned long long adlen = LENGTH;
    /* full associated data blocks */
    if (adlen)
    {
      while (adlen >= ASCON_128_RATE)
      {
        if (threadIdx.x == 0)
          s_x ^= LOADBYTES((const uint8_t *)ad_d, 8);
        // P6
        P6_FIVE(&s_x);

        ad_d += ASCON_128_RATE;
        adlen -= ASCON_128_RATE;
      }
      /* final associated data block */
      if (threadIdx.x == 0)
      {
        s_x ^= LOADBYTES((const uint8_t *)ad_d, adlen);
        s_x ^= PAD(adlen);
      }
      // P6
      P6_FIVE(&s_x);
    }
  }

  /* domain separation */
  if (threadIdx.x == 4)
    s_x ^= 1;

  /* full ciphertext blocks */
  {
    // cipher length + 16 bytes flag= ciphertext
    unsigned long long clen = LENGTH;
    while (clen >= ASCON_128_RATE)
    {
      if (threadIdx.x == 0)
      {
        uint64_t c0 = LOADBYTES((const uint8_t *)ciphertext_d, 8);
        STOREBYTES((uint8_t *)decryptedtext_d, s_x ^ c0, 8);
        s_x = c0;
      }
      // P6
      P6_FIVE(&s_x);
      decryptedtext_d += ASCON_128_RATE;
      ciphertext_d += ASCON_128_RATE;
      clen -= ASCON_128_RATE;
    }

    /* final ciphertext block */
    if (threadIdx.x == 0)
    {
      uint64_t c0 = LOADBYTES((const uint8_t *)ciphertext_d, clen);
      STOREBYTES((uint8_t *)decryptedtext_d, s_x ^ c0, clen);

      s_x = CLEARBYTES(s_x, clen);
      s_x |= c0;
      s_x ^= PAD(clen);

      // Not necessary
      ciphertext_d += clen;
    }

    // The pointer of ciphertext_d is used to check the flag
    // in the following step. But since decide to output the flag
    // so there is no need to use warp shuffle to broadcast the pointer here
  }

  /* finalize */
  if (threadIdx.x == 1 || threadIdx.x == 2)
  {
    s_x ^= kn;
  }

  P12_FIVE(&s_x);

  {
    uint64_t temp = __shfl_up_sync(0x1F, kn, 2);
    if (threadIdx.x == 3 || threadIdx.x == 4)
      s_x ^= temp;
  }

  /* set tag */
  if (threadIdx.x == 3 || threadIdx.x == 4)
  {
    uint8_t *temp = (uint8_t *)flag_d + (threadIdx.x - 3) * 8;
    STOREBYTES(temp, s_x, 8);
  }

  // no need to verify the flag here
  // you can verify the flag according to the output flag_d
}

int main(int argc, char const *argv[])
{
  char *plaintext_h, *ad_h, *ciphertext_h;
  char *plaintext_d, *ad_d, *ciphertext_d;
  char nonce_h[16], key_h[16];

  char *decryptedtext_h, *decryptedtext_d;

  dim3 blockDim(BLOCK_SIZE);
  dim3 gridDim((SIZE + blockDim.x - 1) / blockDim.x);

  // initialize nonce and key and copy to constant memory
  prepare_key_nonce(nonce_h, key_h);
  cudaMemcpyToSymbol(nonce, nonce_h, sizeof(char) * 16);
  cudaMemcpyToSymbol(key, key_h, sizeof(char) * 16);
  // allocate memory for host
  plaintext_h = (char *)malloc(sizeof(char) * LENGTH * SIZE);
  ad_h = (char *)malloc(sizeof(char) * LENGTH * SIZE);
  ciphertext_h = (char *)malloc(sizeof(char) * (LENGTH + 16) * SIZE);
  // allocate memory for device
  cudaMalloc((void **)&plaintext_d, sizeof(char) * LENGTH * SIZE);
  cudaMalloc((void **)&ad_d, sizeof(char) * LENGTH * SIZE);
  cudaMalloc((void **)&ciphertext_d, sizeof(char) * (LENGTH + 16) * SIZE);

  // warm up kernel to avoid first time delay
  warmup_kernel<<<gridDim, blockDim>>>();

  cudaDeviceSynchronize();

  // initialize plaintext and associated data
  prepare_text(plaintext_h, ad_h, SIZE);

  // copy data from host to device
  cudaMemcpy(plaintext_d, plaintext_h, sizeof(char) * LENGTH * SIZE, cudaMemcpyHostToDevice);
  cudaMemcpy(ad_d, ad_h, sizeof(char) * LENGTH * SIZE, cudaMemcpyHostToDevice);

  //================Timer===============↓//
  cudaEvent_t start, stop;
  float elapsedTime;
  cudaEventCreate(&start);
  cudaEventCreate(&stop);

  cudaEventRecord(start, 0);
  //================Timer===============↑//

  // launch kernel
  ascon_encrypt_device<<<gridDim, blockDim>>>(plaintext_d, ad_d, ciphertext_d);

  cudaDeviceSynchronize();

  //================Timer===============↓//
  cudaEventRecord(stop, 0);
  cudaEventSynchronize(stop);
  cudaEventElapsedTime(&elapsedTime, start, stop);
  printf("Basic GPU Encryption=> Time consumed: %f ms\n", elapsedTime);
  printf("Number of encryption executions: %d\n", SIZE);

  //================Timer===============↑//

  // copy ciphertext from device to host
  cudaMemcpy(ciphertext_h, ciphertext_d, sizeof(char) * (LENGTH + 16) * SIZE, cudaMemcpyDeviceToHost);

  // prepare for decryption
  decryptedtext_h = (char *)malloc(sizeof(char) * LENGTH * SIZE);
  cudaMalloc((void **)&decryptedtext_d, sizeof(char) * LENGTH * SIZE);

  // Although ad_d does not change, we still need to copy it to control the exprimental variables
  cudaMemcpy(ad_d, ad_h, sizeof(char) * LENGTH * SIZE, cudaMemcpyHostToDevice);
  cudaMemcpy(ciphertext_d, ciphertext_h, sizeof(char) * (LENGTH + 16) * SIZE, cudaMemcpyHostToDevice);

  //================Timer===============↓//
  cudaEventRecord(start, 0);
  //================Timer===============↑//

  ascon_decrypt_device<<<gridDim, blockDim>>>(ciphertext_d, ad_d, decryptedtext_d);
  cudaDeviceSynchronize();

  //================Timer===============↓//
  cudaEventRecord(stop, 0);
  cudaEventSynchronize(stop);
  cudaEventElapsedTime(&elapsedTime, start, stop);

  printf("Basic GPU decryption=> Time consumed: %f ms\n", elapsedTime);
  printf("Number of decryption executions: %d\n", SIZE);

  //================Timer===============↑//

  // copy decrypted text from device to host
  cudaMemcpy(decryptedtext_h, decryptedtext_d, sizeof(char) * LENGTH * SIZE, cudaMemcpyDeviceToHost);

  // verify correctness
  int error_count = 0;
  for (int i = 0; i < LENGTH * SIZE; i++)
  {
    if (decryptedtext_h[i] != plaintext_h[i])
    {
      error_count++;
    }
  }
  printf("error count: %d\n", error_count);

  //======= Test for fine grained encryption=======

  // prepare for key_and_nonce
  char *key_and_nonce_h, *key_and_nonce_d;
  key_and_nonce_h = (char *)malloc(sizeof(char) * 32);
  cudaMalloc((void **)&key_and_nonce_d, sizeof(char) * 32);

  for (int i = 0; i < 16; i++)
  {
    key_and_nonce_h[i] = key_h[i];

    key_and_nonce_h[i + 16] = nonce_h[i];
    /*
    Please do not write bug like this anymore!!!

    if (i < 8)
      key_and_nonce_h[i] = key_h[i];
    else
      key_and_nonce_h[i] = nonce_h[i];
    */
  }

  cudaMemcpy(key_and_nonce_d, key_and_nonce_h, sizeof(char) * 32, cudaMemcpyHostToDevice);

  // encryption result
  char *fg_ciphertext_h;

  fg_ciphertext_h = (char *)malloc(sizeof(char) * (LENGTH + 16) * SIZE);

  //NB! reset the ciphertext in the device
  //prevent the leftover data to influence the result
  cudaMemset(ciphertext_d,0,sizeof(char) * (LENGTH + 16) * SIZE);

  //================Timer===============↓//
  cudaEventRecord(start, 0);
  //================Timer===============↑//

  // launch kernel
  ascon_encrypt_one_in_five<<<1, 5>>>(plaintext_d, ad_d, key_and_nonce_d, ciphertext_d);

  cudaDeviceSynchronize();

  //================Timer===============↓//
  cudaEventRecord(stop, 0);
  cudaEventSynchronize(stop);
  cudaEventElapsedTime(&elapsedTime, start, stop);

  printf("Fine-grained GPU encryption=> Time consumed: %f ms\n", elapsedTime);
  printf("Number of decryption executions: %d\n", 1);
  //================Timer===============↑//

  // copy decrypted text from device to host
  cudaMemcpy(fg_ciphertext_h, ciphertext_d, sizeof(char) * (LENGTH + 16), cudaMemcpyDeviceToHost);

  // verify correctness
  error_count = 0;
  for (int i = 0; i < LENGTH + 16; i++)
  {
    if (fg_ciphertext_h[i] != ciphertext_h[i])
    {
      error_count++;
      printf("error position: %d\n", i);
    }
  }
  printf("Fine-grained Encrypt error count: %d\n", error_count);

  //======= Test for fine grained decryption=======
  char *flag_d, *flag_h;
  cudaMalloc((void **)&flag_d, sizeof(char) * 16);
  flag_h = (char *)malloc(sizeof(char) * 16);

  //NB! reset the ciphertext in the device
  //prevent the residual data to influence the result
  cudaMemset(decryptedtext_d,0,sizeof(char) * (LENGTH) * SIZE);

  //================Timer===============↓//
  cudaEventRecord(start, 0);
  //================Timer===============↑//

  ascon_decrypt_one_in_five<<<1, 5>>>(ciphertext_d, ad_d, key_and_nonce_d, decryptedtext_d, flag_d);

  cudaDeviceSynchronize();

  //================Timer===============↓//
  cudaEventRecord(stop, 0);
  cudaEventSynchronize(stop);
  cudaEventElapsedTime(&elapsedTime, start, stop);

  printf("Fine-grained GPU decryption=> Time consumed: %f ms\n", elapsedTime);
  printf("Number of decryption executions: %d\n", 1);

  //================Timer===============↑//

  cudaMemcpy(flag_h, flag_d, sizeof(char) * (16), cudaMemcpyDeviceToHost);
  cudaMemcpy(decryptedtext_h, decryptedtext_d, sizeof(char) * (16), cudaMemcpyDeviceToHost);

  // check flag
  error_count = 0;
  for (int i = 0; i < 16; i++)
  {
    if (ciphertext_h[i + LENGTH] != flag_h[i])
    {
      error_count++;
      printf("Flag error position: %d\n", i);
    }
  }
  printf("Fine-grained decrypt error count for Flag: %d\n", error_count);

  // chekc text

  error_count = 0;
  for (int i = 0; i < LENGTH; i++)
  {
    if (plaintext_h[i] != decryptedtext_h[i])
    {
      error_count++;
      printf("Text error position: %d\n", i);
    }
  }
  printf("Fine-grained decrypt error count for Text: %d\n", error_count);

  //======= Test for fine grained decryption=======
  // free memory
  free(plaintext_h);
  free(ad_h);
  free(ciphertext_h);

  free(decryptedtext_h);
  free(key_and_nonce_h);
  free(fg_ciphertext_h);
  free(flag_h);

  cudaFree(plaintext_d);
  cudaFree(ad_d);
  cudaFree(ciphertext_d);

  cudaFree(decryptedtext_d);
  cudaFree(key_and_nonce_d);
  cudaFree(flag_d);

  return 0;
}