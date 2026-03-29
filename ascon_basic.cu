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

__host__ __device__ int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k) {
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
  //printstate("initialization", &s);

  if (adlen) {
    /* full associated data blocks */
    while (adlen >= ASCON_128_RATE) {
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
  //printstate("process associated data", &s);

  /* full plaintext blocks */
  while (mlen >= ASCON_128_RATE) {
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
  //printstate("process plaintext", &s);

  /* finalize */
  s.x1 ^= K0;
  s.x2 ^= K1;
  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;
  //printstate("finalization", &s);

  /* set tag */
  STOREBYTES(c, s.x3, 8);
  STOREBYTES(c + 8, s.x4, 8);

  return 0;
}

/* ============================================================
 * FROM: decrypt.c
 * ============================================================ */

__host__ __device__ int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,
                        unsigned char* nsec, const unsigned char* c,
                        unsigned long long clen, const unsigned char* ad,
                        unsigned long long adlen, const unsigned char* npub,
                        const unsigned char* k) {
  (void)nsec;

  if (clen < CRYPTO_ABYTES) return -1;

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
  //printstate("initialization", &s);

  if (adlen) {
    /* full associated data blocks */
    while (adlen >= ASCON_128_RATE) {
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
  //printstate("process associated data", &s);

  /* full ciphertext blocks */
  clen -= CRYPTO_ABYTES;
  while (clen >= ASCON_128_RATE) {
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
  //printstate("process ciphertext", &s);

  /* finalize */
  s.x1 ^= K0;
  s.x2 ^= K1;
  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;
  //printstate("finalization", &s);

  /* set tag */
  uint8_t t[16];
  STOREBYTES(t, s.x3, 8);
  STOREBYTES(t + 8, s.x4, 8);

  /* verify tag (should be constant time, check compiler output) */
  int result = 0;
  for (int i = 0; i < CRYPTO_ABYTES; ++i) result |= c[i] ^ t[i];
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

//for palintext and associated data
#define LENGTH 16
//How many times of encryption/decryption do you want to perform
#define SIZE 10240000

#define BLOCK_SIZE 256

__constant__ char nonce[16];

__constant__ char key[16];

__global__ void ascon_encrypt_device(char* plaintext_d, char* ad_d, char * ciphertext_d){
    //a dummy variable to hold the length of ciphertext
    //actually it is LENGTH + 16 Bytes tag
    unsigned long long clen;
    int tid= threadIdx.x + blockIdx.x * blockDim.x;

    char* plaintext=LENGTH*tid + plaintext_d;
    char* ad=LENGTH*tid + ad_d;
    char* ciphertext=(LENGTH+16)*tid + ciphertext_d;

    crypto_aead_encrypt((unsigned char*)ciphertext, &clen,
                        (const unsigned char*)plaintext, LENGTH,
                        (const unsigned char*)ad, LENGTH,
                        NULL, (const unsigned char*)nonce,
                        (const unsigned char*)key);

}
__global__ void ascon_decrypt_device(char* ciphertext_d, char* ad_d, char * decryptedtext_d){
    //a dummy variable to hold the length of plaintext
    //actually it is LENGTH Bytes
    unsigned long long mlen;
    int tid= threadIdx.x + blockIdx.x * blockDim.x;
    

    char* ciphertext=(LENGTH+16)*tid + ciphertext_d;
    char* ad=LENGTH*tid + ad_d;
    char* decryptedtext=LENGTH*tid + decryptedtext_d;

    crypto_aead_decrypt((unsigned char*)decryptedtext, &mlen,
                        NULL, (const unsigned char*)ciphertext,
                        LENGTH + 16,
                        (const unsigned char*)ad, LENGTH,
                        (const unsigned char*)nonce,
                        (const unsigned char*)key);

}

__global__ void warmup_kernel(){
    //do nothing
    return;
}




__host__ void CPU_implementation(){
    //This function do the CPU implementation of Ascon encryption and decryption
    char* plaintext,* ciphertext, * decryptedtext,* ad;
    char nonce[16], key[16];

    //initialize virables
    prepare_key_nonce(key,nonce);
    plaintext=(char*)malloc(sizeof(char)*LENGTH*SIZE);
    ad=(char*)malloc(sizeof(char)*LENGTH*SIZE);
    ciphertext=(char*)malloc(sizeof(char)*(LENGTH+16)*SIZE);
    decryptedtext=(char*)malloc(sizeof(char)*LENGTH*SIZE);
    prepare_text(plaintext,ad,SIZE);

    uint64_t count=0;
    //dummy variable to hold the length of ciphertext
    unsigned long long clen;
        //================Timing Unit===============↓//
        LARGE_INTEGER freq, t0, t1;
        QueryPerformanceFrequency(&freq);

        QueryPerformanceCounter(&t0);
        //================Timing Unit===============↑//
    while(count<SIZE){
        crypto_aead_encrypt((unsigned char*)(ciphertext+count*(LENGTH+16)), &clen,
                        (const unsigned char*)(plaintext+count*LENGTH), LENGTH,
                        (const unsigned char*)(ad+count*LENGTH), LENGTH,
                        NULL, (const unsigned char*)nonce,
                        (const unsigned char*)key);
        count++;
    }
        //================Timer===============↓//
        QueryPerformanceCounter(&t1);
        {
        double ms =
            (double)(t1.QuadPart - t0.QuadPart) * 1000.0 /freq.QuadPart;
        printf("CPU Encryption=> Time consumed: %f ms\n", ms);
        printf("Number of encryption executions: %d\n", SIZE);
        }
        //================Timer===============↑//
    
    count=0;
    //dummy variable to hold the length of plaintext
    unsigned long long mlen;

        //================Timing Unit===============↓//
        QueryPerformanceCounter(&t0);
        //================Timing Unit===============↑//
    while(count<SIZE){
        crypto_aead_decrypt((unsigned char*)(decryptedtext+count*LENGTH), &mlen,
                        NULL, (const unsigned char*)(ciphertext+count*(LENGTH+16)),
                        LENGTH + 16,
                        (const unsigned char*)(ad+count*LENGTH), LENGTH,
                        (const unsigned char*)nonce,
                        (const unsigned char*)key);
        count++;
    }
        //================Timer===============↓//
        QueryPerformanceCounter(&t1);
        {
        double ms =
            (double)(t1.QuadPart - t0.QuadPart) * 1000.0 /freq.QuadPart;
        printf("CPU decryption=> Time consumed: %f ms\n", ms);
        printf("Number of decryption executions: %d\n", SIZE);
        }
        //================Timer===============↑//
    
    //verify correctness
    int error_count=0;
    for (int i = 0; i < LENGTH*SIZE; i++)
    {
        if(decryptedtext[i]!=plaintext[i]){
            error_count++;
        }
    }
    printf("error count: %d\n",error_count);

    //free memory
    free(plaintext);
    free(ad);
    free(ciphertext);
    free(decryptedtext);
    
}

int main(int argc, char const *argv[])
{
    char* plaintext_h,* ad_h, *ciphertext_h;
    char *plaintext_d, *ad_d, *ciphertext_d;
    char nonce_h[16], key_h[16];

    char* decryptedtext_h, *decryptedtext_d;

    dim3 blockDim(BLOCK_SIZE);
    dim3 gridDim((SIZE + blockDim.x - 1) / blockDim.x);

    //=====================CPU Implementation=====================//
    CPU_implementation();
    //=====================GPU Implementation=====================//

    //initialize nonce and key and copy to constant memory
    prepare_key_nonce(nonce_h,key_h);
    cudaMemcpyToSymbol(nonce,nonce_h,sizeof(char)*16);
    cudaMemcpyToSymbol(key,key_h,sizeof(char)*16);
    //allocate memory for host
    plaintext_h=(char*)malloc(sizeof(char)*LENGTH*SIZE);
    ad_h=(char*)malloc(sizeof(char)*LENGTH*SIZE);
    ciphertext_h=(char*)malloc(sizeof(char)*(LENGTH+16)*SIZE);
    //allocate memory for device
    cudaMalloc((void**)&plaintext_d,sizeof(char)*LENGTH*SIZE);
    cudaMalloc((void**)&ad_d,sizeof(char)*LENGTH*SIZE);
    cudaMalloc((void**)&ciphertext_d,sizeof(char)*(LENGTH+16)*SIZE);

    //warm up kernel to avoid first time delay
    warmup_kernel<<<gridDim,blockDim>>>();
        
    cudaDeviceSynchronize();

    //initialize plaintext and associated data
    prepare_text(plaintext_h,ad_h,SIZE);

        //================Timing Unit===============↓//
        LARGE_INTEGER freq, t0, t1;
        QueryPerformanceFrequency(&freq);

        QueryPerformanceCounter(&t0);
        //================Timing Unit===============↑//

    
   
    //copy data from host to device
    cudaMemcpy(plaintext_d,plaintext_h,sizeof(char)*LENGTH*SIZE,cudaMemcpyHostToDevice);
    cudaMemcpy(ad_d,ad_h,sizeof(char)*LENGTH*SIZE,cudaMemcpyHostToDevice);


    //launch kernel

    ascon_encrypt_device<<<gridDim,blockDim>>>(plaintext_d,ad_d,ciphertext_d);
        
    cudaDeviceSynchronize();
    //copy ciphertext from device to host
    cudaMemcpy(ciphertext_h,ciphertext_d,sizeof(char)*(LENGTH+16)*SIZE,cudaMemcpyDeviceToHost);
        //================Timer===============↓//
        QueryPerformanceCounter(&t1);
        {
        double ms =
            (double)(t1.QuadPart - t0.QuadPart) * 1000.0 /freq.QuadPart;
        printf("Basic GPU Encryption=> Time consumed: %f ms\n", ms);
        printf("Number of encryption executions: %d\n", SIZE);
        }
        //================Timer===============↑//
    
    //prepare for decryption
    decryptedtext_h=(char*)malloc(sizeof(char)*LENGTH*SIZE);
    cudaMalloc((void**)&decryptedtext_d,sizeof(char)*LENGTH*SIZE);

        //================Timing Unit===============↓//
        QueryPerformanceCounter(&t0);
        //================Timing Unit===============↑//
    
    //Although ad_d does not change, we still need to copy it to control the exprimental variables
    cudaMemcpy(ad_d,ad_h,sizeof(char)*LENGTH*SIZE,cudaMemcpyHostToDevice);
    cudaMemcpy(ciphertext_d,ciphertext_h,sizeof(char)*(LENGTH+16)*SIZE,cudaMemcpyHostToDevice);

    ascon_decrypt_device<<<gridDim,blockDim>>>(ciphertext_d,ad_d,decryptedtext_d);
    cudaDeviceSynchronize();
    //copy decrypted text from device to host
    cudaMemcpy(decryptedtext_h,decryptedtext_d,sizeof(char)*LENGTH*SIZE,cudaMemcpyDeviceToHost);
        //================Timer===============↓//
        QueryPerformanceCounter(&t1);
        {
        double ms =
            (double)(t1.QuadPart - t0.QuadPart) * 1000.0 /freq.QuadPart;
        printf("Basic GPU decryption=> Time consumed: %f ms\n", ms);
        printf("Number of decryption executions: %d\n", SIZE);
        }
        //================Timer===============↑//

    //verify correctness
    int error_count=0;
    for (int i = 0; i < LENGTH*SIZE; i++)
    {
        if(decryptedtext_h[i]!=plaintext_h[i]){
            error_count++;
        }
    }
    printf("error count: %d\n",error_count);
   
    printf("Even though in the GPU implementaion, data need to be transferred from host to device, but the results shows that it is worth it\n");
    //free memory
    free(plaintext_h);
    free(ad_h);
    free(ciphertext_h);
    cudaFree(plaintext_d);
    cudaFree(ad_d);
    cudaFree(ciphertext_d);



    return 0;
}


