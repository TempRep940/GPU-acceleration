#ifndef CRYPTO_AEAD_H
#define CRYPTO_AEAD_H

/**
 * Encrypts a message with associated data using ASCON-128 AEAD
 *
 * @param c      Output: ciphertext + tag
 * @param clen   Output: length of ciphertext + tag
 * @param m      Input: plaintext message
 * @param mlen   Input: length of plaintext
 * @param ad     Input: associated data (authenticated but not encrypted)
 * @param adlen  Input: length of associated data
 * @param nsec   Input: not used (should be NULL)
 * @param npub   Input: public nonce (16 bytes)
 * @param k      Input: secret key (16 bytes)
 * @return       0 on success
 */
int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k);

/**
 * Decrypts and authenticates a ciphertext with associated data using ASCON-128 AEAD
 *
 * @param m      Output: plaintext message
 * @param mlen   Output: length of plaintext
 * @param nsec   Input: not used (should be NULL)
 * @param c      Input: ciphertext + tag
 * @param clen   Input: length of ciphertext + tag
 * @param ad     Input: associated data (must match encryption)
 * @param adlen  Input: length of associated data
 * @param npub   Input: public nonce (must match encryption, 16 bytes)
 * @param k      Input: secret key (must match encryption, 16 bytes)
 * @return       0 on success, -1 if authentication fails
 */
int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,
                        unsigned char* nsec, const unsigned char* c,
                        unsigned long long clen, const unsigned char* ad,
                        unsigned long long adlen, const unsigned char* npub,
                        const unsigned char* k);

#endif /* CRYPTO_AEAD_H */