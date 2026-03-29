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
//=====================GPU pipeline developeent=====================↓//

//for palintext and associated data
#define LENGTH 16
//How many times of encryption/decryption do you want to perform (Total)
#define SIZE 10240000
//How many data is processed in one kernel launch
//The Batch size must be large enough, otherwise it is not worth it to do additional schedualing(overhead) for the pipelines(streams)
#define BATCH 1024000 
//How many streams do you want to use
#define STREAM_NUM 4

#define BLOCK_SIZE 256

__constant__ char nonce[16];

__constant__ char key[16];

__global__ void ascon_encrypt_device(char* plaintext_d, char* ad_d, char * ciphertext_d){
    //a dummy variable to hold the length of ciphertext
    //actually it is LENGTH + 16 Bytes tag
    unsigned long long clen;
    int tid= threadIdx.x + blockIdx.x * blockDim.x;
    
    /*
    uint64_t global_tid=offset*BATCH + tid;

    if (global_tid>=SIZE) return;
    */
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
    /*
    uint64_t global_tid=offset*BATCH + tid;

    if (global_tid>=SIZE) return;
    */
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


//offset: which Batch is processed. Batch number start from 0
__host__ void async_ascon_encrypt(char* plaintext, char* ad, char * ciphertext, uint64_t offset,cudaStream_t stream){


    char* plaintext_h=offset*BATCH*LENGTH + plaintext;
    char* ad_h=offset*BATCH*LENGTH + ad;
    char* ciphertext_h=offset*BATCH*(LENGTH+16) + ciphertext;

    dim3 block_dim(BLOCK_SIZE);
    dim3 grid_dim((BATCH + block_dim.x - 1) / block_dim.x);

    char *plaintext_d, *ad_d, *ciphertext_d;

    cudaMalloc((void**)&plaintext_d,sizeof(char)*LENGTH*BATCH);
    cudaMalloc((void**)&ad_d,sizeof(char)*LENGTH*BATCH);
    cudaMalloc((void**)&ciphertext_d,sizeof(char)*(LENGTH+16)*BATCH);

    cudaMemcpyAsync(plaintext_d,plaintext_h,sizeof(char)*LENGTH*BATCH,cudaMemcpyHostToDevice,stream);
    cudaMemcpyAsync(ad_d,ad_h,sizeof(char)*LENGTH*BATCH,cudaMemcpyHostToDevice,stream);

    ascon_encrypt_device<<<grid_dim,block_dim,0,stream>>>(plaintext_d,ad_d,ciphertext_d);
    cudaMemcpyAsync(ciphertext_h,ciphertext_d,sizeof(char)*(LENGTH+16)*BATCH,cudaMemcpyDeviceToHost,stream);

    //Use cudaFree may block the CPU to wait for the GPU until GPU finishes the kernel
    cudaFreeAsync(plaintext_d,stream);
    cudaFreeAsync(ad_d,stream);
    cudaFreeAsync(ciphertext_d,stream);

    return;

}

//offset: which Batch is processed. Batch number start from 0
__host__ void async_ascon_decrypt(char* ciphertext, char* ad, char * decryptedtext, uint64_t offset,cudaStream_t stream){


    char* decryptedtext_h=offset*BATCH*LENGTH + decryptedtext;
    char* ad_h=offset*BATCH*LENGTH + ad;
    char* ciphertext_h=offset*BATCH*(LENGTH+16) + ciphertext;

    dim3 block_dim(BLOCK_SIZE);
    dim3 grid_dim((BATCH + block_dim.x - 1) / block_dim.x);

    char *decryptedtext_d, *ad_d, *ciphertext_d;

    cudaMalloc((void**)&decryptedtext_d,sizeof(char)*LENGTH*BATCH);
    cudaMalloc((void**)&ad_d,sizeof(char)*LENGTH*BATCH);
    cudaMalloc((void**)&ciphertext_d,sizeof(char)*(LENGTH+16)*BATCH);

    cudaMemcpyAsync(ad_d,ad_h,sizeof(char)*LENGTH*BATCH,cudaMemcpyHostToDevice,stream);
    cudaMemcpyAsync(ciphertext_d,ciphertext_h,sizeof(char)*(LENGTH+16)*BATCH,cudaMemcpyHostToDevice,stream);

    ascon_decrypt_device<<<grid_dim,block_dim,0,stream>>>(ciphertext_d,ad_d,decryptedtext_d);

    cudaMemcpyAsync(decryptedtext_h,decryptedtext_d,sizeof(char)*LENGTH*BATCH,cudaMemcpyDeviceToHost,stream);

    //Use cudaFree may block the CPU to wait for the GPU until GPU finishes the kernel
    cudaFreeAsync(decryptedtext_d,stream);
    cudaFreeAsync(ad_d,stream);
    cudaFreeAsync(ciphertext_d,stream);

    return;
}
    

int main(int argc, char const *argv[])
{
    char* plaintext_h,* ad_h, *ciphertext_h;
    
    char nonce_h[16], key_h[16];

    char* decryptedtext_h;

    //padding the last batch if SIZE is not multiple of BATCH
    uint64_t padding_size=(SIZE+BATCH-1)/BATCH*BATCH;


    //initialize nonce and key and copy to constant memory
    prepare_key_nonce(nonce_h,key_h);
    cudaMemcpyToSymbol(nonce,nonce_h,sizeof(char)*16);
    cudaMemcpyToSymbol(key,key_h,sizeof(char)*16);

    //allocate memory for host
    //But notice that pinned page memory should be used for different streams

    cudaMallocHost((void**)&plaintext_h,sizeof(char)*LENGTH*padding_size);
    cudaMallocHost((void**)&ad_h,sizeof(char)*LENGTH*padding_size);
    cudaMallocHost((void**)&ciphertext_h,sizeof(char)*(LENGTH+16)*padding_size);
    
    
    dim3 block_dim(BLOCK_SIZE);
    dim3 grid_dim((BATCH + block_dim.x - 1) / block_dim.x);
    //warm up kernel to avoid first time delay
    warmup_kernel<<<grid_dim,block_dim>>>();


    
    cudaDeviceSynchronize();

    //initialize plaintext and associated data
    prepare_text(plaintext_h,ad_h,SIZE);

    //Total number of batches
    int total_batches=(SIZE+BATCH-1)/BATCH;
    int count=0;
    //create streams
    cudaStream_t streams[STREAM_NUM];

    for (int i = 0; i < STREAM_NUM; i++)
    {
        cudaStreamCreate(&streams[i]);
    }

    //Set kernel as L1 Cache preferred
    //No big difference, even a little bit slower while decryption
    //cudaFuncSetCacheConfig(ascon_encrypt_device, cudaFuncCachePreferL1);
    //cudaFuncSetCacheConfig(ascon_decrypt_device, cudaFuncCachePreferL1);

        //================Timing Unit===============↓//
        LARGE_INTEGER freq, t0, t1;
        QueryPerformanceFrequency(&freq);

        QueryPerformanceCounter(&t0);
        //================Timing Unit===============↑//

    //Round Robin
    while(count<total_batches){
        int temp=count%STREAM_NUM;
        async_ascon_encrypt(plaintext_h,ad_h,ciphertext_h,count,streams[temp]);
        count++;
    }

    //wait for all streams to finish
    cudaDeviceSynchronize();

        //================Timer===============↓//
        QueryPerformanceCounter(&t1);
        {
        double ms =
            (double)(t1.QuadPart - t0.QuadPart) * 1000.0 /freq.QuadPart;
        printf("GPU pipeline Encryption=> Time consumed: %f ms\n", ms);
        printf("Number of encryption executions: %d\n", SIZE);
        }
        //================Timer===============↑//
    



    //prepare for decryption
    cudaMallocHost((void**)&decryptedtext_h,sizeof(char)*LENGTH*padding_size);

        //================Timing Unit===============↓//
        QueryPerformanceCounter(&t0);
        //================Timing Unit===============↑//
    
    //initialize count again
    count=0;
    //Round Robin
    while(count<total_batches){
        int temp=count%STREAM_NUM;
        async_ascon_decrypt(ciphertext_h,ad_h,decryptedtext_h,count,streams[temp]);
        count++;
    }

    cudaDeviceSynchronize();


        //================Timer===============↓//
        QueryPerformanceCounter(&t1);
        {
        double ms =
            (double)(t1.QuadPart - t0.QuadPart) * 1000.0 /freq.QuadPart;
        printf("GPU pipeline decryption=> Time consumed: %f ms\n", ms);
        printf("Number of decryption executions: %d\n", SIZE);
        }
        //================Timer===============↑//

    //verify correctness
    int error_count=0;
    for (int i = 0; i < LENGTH*SIZE; i++)
    {
        if(decryptedtext_h[i]!=plaintext_h[i]){
            error_count++;
            printf("error at byte %d: original %02x, decrypted %02x\n",i,(unsigned char)plaintext_h[i],(unsigned char)decryptedtext_h[i]);
        }
        
    }
    printf("\nerror count: %d\n",error_count);
   
    
    
    //free memory
    free(plaintext_h);
    free(ad_h);
    free(ciphertext_h);
    free(decryptedtext_h);



    return 0;
}