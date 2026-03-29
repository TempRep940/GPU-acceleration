//AI generated test case
#include <stdint.h>
#include <stdio.h>
#include <cuda_runtime.h>

#define ROR(x,n) (((x)>>(n)) | ((x)<<(64-(n))))

typedef struct {
  uint64_t x0, x1, x2, x3, x4;
} state_t;

/* ================= Debug helpers ================= */

static inline void debug_print_cpu(const char *tag, const state_t *s)
{
  printf("[CPU] %-30s : %016llx %016llx %016llx %016llx %016llx\n",
         tag,
         (unsigned long long)s->x0,
         (unsigned long long)s->x1,
         (unsigned long long)s->x2,
         (unsigned long long)s->x3,
         (unsigned long long)s->x4);
}

__device__ static inline void debug_print_gpu(const char *tag, uint64_t v)
{
  printf("[GPU] %-30s : tid=%d value=%016llx\n",
         tag, threadIdx.x, (unsigned long long)v);
}

/* ================= CPU reference implementation ================= */

static inline void ROUND(state_t* s, uint8_t C) {
  state_t t;

  /* addition of round constant */
  s->x2 ^= C;
  debug_print_cpu("after round constant", s);

  /* substitution layer (xor pre-mix) */
  s->x0 ^= s->x4;
  s->x4 ^= s->x3;
  s->x2 ^= s->x1;
  debug_print_cpu("after substitution pre-mix", s);

  /* start of keccak s-box */
  t.x0 = s->x0 ^ (~s->x1 & s->x2);
  t.x1 = s->x1 ^ (~s->x2 & s->x3);
  t.x2 = s->x2 ^ (~s->x3 & s->x4);
  t.x3 = s->x3 ^ (~s->x4 & s->x0);
  t.x4 = s->x4 ^ (~s->x0 & s->x1);
  debug_print_cpu("after keccak s-box (raw)", &t);
  /* end of keccak s-box */

  t.x1 ^= t.x0;
  t.x0 ^= t.x4;
  t.x3 ^= t.x2;
  t.x2 = ~t.x2;
  debug_print_cpu("after s-box post-mix", &t);

  /* linear diffusion layer */
  s->x0 = t.x0 ^ ROR(t.x0, 19) ^ ROR(t.x0, 28);
  s->x1 = t.x1 ^ ROR(t.x1, 61) ^ ROR(t.x1, 39);
  s->x2 = t.x2 ^ ROR(t.x2, 1)  ^ ROR(t.x2, 6);
  s->x3 = t.x3 ^ ROR(t.x3, 10) ^ ROR(t.x3, 17);
  s->x4 = t.x4 ^ ROR(t.x4, 7)  ^ ROR(t.x4, 41);
  debug_print_cpu("after linear diffusion", s);
}

/* ================= GPU optimized implementation (NEW ROUND_FIVE) ================= */

__device__ static __forceinline__ void ROUND_FIVE(uint64_t * s_x, uint8_t C){
  /* addition of round constant */
  if (threadIdx.x==2) *s_x ^= C;
  debug_print_gpu("after round constant", *s_x);

  /* substitution layer */
  {
    uint64_t temp=0;
    temp=__shfl_sync(0x1F,*s_x,4);
    if (threadIdx.x==0) //Run thread 0 first because of data dependency
    {
      
      *s_x ^= temp;
    }
    temp=__shfl_up_sync(0x1F,*s_x,1);
    if(threadIdx.x==2||threadIdx.x==4)
    { 
      
      *s_x ^= temp;
    }
    debug_print_gpu("after substitution pre-mix", *s_x);
  }

  /* start of keccak s-box */
  {
    uint64_t temp1=0;
    uint64_t temp2=0;

    temp1=__shfl_sync(0x1F,*s_x,(threadIdx.x+1)%5);
    temp2=__shfl_sync(0x1F,*s_x,(threadIdx.x+2)%5);

    *s_x=*s_x ^((~temp1)&temp2);
  }
  /* end of keccak s-box */
  debug_print_gpu("after keccak s-box (raw)", *s_x);

  /* only thread 0,1,3 participate */
    {
    uint64_t temp=0;

    temp=__shfl_sync(0x1F,*s_x,(threadIdx.x+4)%5);
    if(threadIdx.x==1) *s_x ^= temp;

    if (threadIdx.x==0||threadIdx.x==3)
    { 
      *s_x ^= temp;
    }
  }
  debug_print_gpu("after s-box post-mix", *s_x);

  if (threadIdx.x==2)
  {
    *s_x= ~*s_x;
  }

  /* linear diffusion layer */
  {
    int temp1=0;
    int temp2=0;

    switch (threadIdx.x)
    {
      case 0:
        temp1=19;
        temp2=28;
        break;
      case 1:
        temp1=61;
        temp2=39;
        break;
      case 2:
        temp1=1;
        temp2=6;
        break;
      case 3:
        temp1=10;
        temp2=17;
        break;
      case 4:
        temp1=7;
        temp2=41;
        break;
    }
    *s_x= *s_x ^ ROR(*s_x, temp1) ^ ROR(*s_x, temp2);
  }
  debug_print_gpu("after linear diffusion", *s_x);
}

/* ================= GPU test kernel ================= */

__global__ void test_round_kernel(uint64_t *d_state, uint8_t C)
{
  if (threadIdx.x < 5) {
    ROUND_FIVE(&d_state[threadIdx.x], C);
  }
}

/* ================= Test driver ================= */

int main()
{
    /* initialize input state */
    state_t s_cpu = {
        0x0023456789abcdefULL,
        0x1edcba9876543210ULL,
        0x1f0f0f0f0f0f0f0fULL,
        0x20f0f0f0f0f0f0f0ULL,
        0xa1aaaaaaaaaaaaaaULL
    };

    uint64_t h_gpu[5] = {
        s_cpu.x0, s_cpu.x1, s_cpu.x2, s_cpu.x3, s_cpu.x4
    };

    uint8_t C = 0x3c;

    /* CPU computation */
    ROUND(&s_cpu, C);

    /* GPU computation */
    uint64_t *d_state;
    cudaMalloc(&d_state, 5 * sizeof(uint64_t));
    cudaMemcpy(d_state, h_gpu, 5 * sizeof(uint64_t), cudaMemcpyHostToDevice);

    test_round_kernel<<<1,5>>>(d_state, C);
    cudaDeviceSynchronize();

    cudaMemcpy(h_gpu, d_state, 5 * sizeof(uint64_t), cudaMemcpyDeviceToHost);
    cudaFree(d_state);

    /* compare results */
    uint64_t cpu[5] = {
        s_cpu.x0, s_cpu.x1, s_cpu.x2, s_cpu.x3, s_cpu.x4
    };

    int ok = 1;
    for (int i = 0; i < 5; i++) {
        if (cpu[i] != h_gpu[i]) {
            printf("Mismatch at x%d: CPU=%016llx GPU=%016llx\n",
                   i,
                   (unsigned long long)cpu[i],
                   (unsigned long long)h_gpu[i]);
            ok = 0;
        }
    }

    if (ok) {
        printf("ROUND and ROUND_FIVE results match.\n");
    }

    return 0;
}
