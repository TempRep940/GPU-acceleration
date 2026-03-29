//AI generated code
/* Merged ASCON Implementation with Test
 * Combines: encrypt.c, decrypt.c, printstate.c, test_ascon.c
 * All .h files are in the 'header' subdirectory
 */

#include "header/api.h"
#include "header/ascon.h"
#include "header/crypto_aead.h"
#include "header/permutations.h"
#include "header/printstate.h"
#include "header/word.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* ============================================================
 * FROM: printstate.c
 * ============================================================ */

#ifdef ASCON_PRINTSTATE

#include "printstate.h"

#include <inttypes.h>
#include <stdio.h>

void printword(const char* text, const word_t x) {
  printf("%s=%016" PRIx64 "\n", text, WORDTOU64(x));
}

void printstate(const char* text, const state_t* s) {
  printf("%s:\n", text);
  printword("  x0", s->x0);
  printword("  x1", s->x1);
  printword("  x2", s->x2);
  printword("  x3", s->x3);
  printword("  x4", s->x4);
}

#endif

/* ============================================================
 * FROM: encrypt.c
 * ============================================================ */

int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
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
  printstate("initialization", &s);

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
  printstate("process associated data", &s);

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
  printstate("process plaintext", &s);

  /* finalize */
  s.x1 ^= K0;
  s.x2 ^= K1;
  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;
  printstate("finalization", &s);

  /* set tag */
  STOREBYTES(c, s.x3, 8);
  STOREBYTES(c + 8, s.x4, 8);

  return 0;
}

/* ============================================================
 * FROM: decrypt.c
 * ============================================================ */

int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,
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
  printstate("initialization", &s);

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
  printstate("process associated data", &s);

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
  printstate("process ciphertext", &s);

  /* finalize */
  s.x1 ^= K0;
  s.x2 ^= K1;
  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;
  printstate("finalization", &s);

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

/* ============================================================
 * FROM: test_ascon.c (main function)
 * ============================================================ */

/* Hex printing helper */
static void print_hex(const char *label, const unsigned char *buf, size_t len) {
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
        if ((i+1) % 32 == 0) printf("\n");
        else if ((i+1) % 2 == 0) printf(" ");
    }
    printf("\n\n");
}

int main(void) {
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
    const unsigned char plaintext[] = "I am the King of vibe coding";
    
    /* Associated Data (authenticated but not encrypted) */
    const unsigned char ad[] = "Associated Data example";

    unsigned long long pt_len = strlen((const char *)plaintext);
    unsigned long long ad_len = strlen((const char *)ad);

    /* Allocate buffer for ciphertext (plaintext + 16 bytes tag) */
    unsigned char *ciphertext = (unsigned char *)malloc(pt_len + 16);
    unsigned long long ct_len = 0;

    printf("============ ASCON-128 Encryption ============\n\n");

    /* ENCRYPT */
    int ret = crypto_aead_encrypt(
        ciphertext, &ct_len,
        plaintext, pt_len,
        ad, ad_len,
        NULL,           /* nsec (not used) */
        nonce,
        key
    );

    if (ret != 0) {
        printf("Encryption failed! ret=%d\n", ret);
        free(ciphertext);
        return 1;
    }

    /* Print encryption info */
    print_hex("Key", key, sizeof(key));
    print_hex("Nonce", nonce, sizeof(nonce));
    print_hex("Associated Data", ad, ad_len);
    printf("Plaintext: %s\n\n", plaintext);
    print_hex("Ciphertext + Tag", ciphertext, ct_len);

    printf("============ ASCON-128 Decryption ============\n\n");

    /* Allocate buffer for recovered plaintext */
    unsigned char *recovered = (unsigned char *)malloc(pt_len + 16);
    unsigned long long recovered_len = 0;

    /* DECRYPT */
    ret = crypto_aead_decrypt(
        recovered, &recovered_len,
        NULL,           /* nsec (not used) */
        ciphertext, ct_len,
        ad, ad_len,
        nonce,
        key
    );

    if (ret != 0) {
        printf("Decryption failed! Authentication tag mismatch! ret=%d\n", ret);
        free(ciphertext);
        free(recovered);
        return 2;
    }

    /* Print decryption info */
    printf("Recovered plaintext length: %llu bytes\n", recovered_len);
    recovered[recovered_len] = '\0';  /* Null-terminate for printing */
    printf("Recovered plaintext: %s\n\n", recovered);

    /* Verify correctness */
    if (recovered_len == pt_len && memcmp(plaintext, recovered, pt_len) == 0) {
        printf("SUCCESS: Decrypted plaintext matches original!\n");
    } else {
        printf("ERROR: Plaintext mismatch!\n");
    }

    /* Test with wrong key (should fail) */
    printf("\n============ Testing Authentication (Wrong Key) ============\n\n");
    unsigned char wrong_key[16] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
    };

    ret = crypto_aead_decrypt(
        recovered, &recovered_len,
        NULL,
        ciphertext, ct_len,
        ad, ad_len,
        nonce,
        wrong_key  /* Wrong key! */
    );

    if (ret != 0) {
        printf("CORRECT: Decryption rejected with wrong key (ret=%d)\n", ret);
    } else {
        printf("ERROR: Decryption should have failed with wrong key!\n");
    }

    /* Cleanup */
    free(ciphertext);
    free(recovered);
    
    return 0;
}