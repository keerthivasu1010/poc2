/**
 * @file sha256.h
 * @brief SHA-256 cryptographic hash function interface.
 *
 * Implements the SHA-256 message digest algorithm as specified in
 * FIPS PUB 180-4. Used throughout the platform for password/PIN
 * hashing and transaction integrity verification.
 */

#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_BLOCK_SIZE 32U      /* 256 bits = 32 bytes            */
#define SHA256_HEX_LEN    64U      /* 32 bytes as hex string          */
#define SHA256_HEX_BUF    65U      /* hex string + NUL terminator     */

typedef struct
{
    uint8_t  data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

/**
 * @brief Initialise a SHA-256 context.
 * @param ctx Pointer to context to initialise. Must not be NULL.
 */
void sha256_init(SHA256_CTX *ctx);

/**
 * @brief Feed data into an in-progress SHA-256 computation.
 * @param ctx  Initialised context.
 * @param data Pointer to input bytes.
 * @param len  Number of bytes in data.
 */
void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len);

/**
 * @brief Finalise the SHA-256 computation and produce the digest.
 * @param ctx  Initialised/updated context.
 * @param hash Output buffer of at least SHA256_BLOCK_SIZE bytes.
 */
void sha256_final(SHA256_CTX *ctx, uint8_t hash[]);

/**
 * @brief Convenience helper: hash a NUL-terminated string and return
 *        the result as a lowercase hex string.
 *
 * @param input     NUL-terminated input string.
 * @param outHex    Output buffer, must be at least SHA256_HEX_BUF bytes.
 * @return 0 on success, -1 on invalid arguments.
 */
int sha256_hash_string(const char *input, char outHex[SHA256_HEX_BUF]);

/**
 * @brief Hash an arbitrary buffer and return the result as hex.
 *
 * @param input   Pointer to input bytes.
 * @param len     Length of input in bytes.
 * @param outHex  Output buffer, must be at least SHA256_HEX_BUF bytes.
 * @return 0 on success, -1 on invalid arguments.
 */
int sha256_hash_buffer(const uint8_t *input, size_t len, char outHex[SHA256_HEX_BUF]);

#endif /* SHA256_H */
