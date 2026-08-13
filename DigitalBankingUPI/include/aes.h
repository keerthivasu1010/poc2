/**
 * @file aes.h
 * @brief AES-128 (ECB mode with PKCS#7 padding) encryption interface.
 *
 * This module implements the AES-128 block cipher from FIPS PUB 197
 * for use in encrypting sensitive transaction payloads before they
 * are written to persistent storage. ECB mode with PKCS#7 padding is
 * used for simplicity of demonstration; a production system should
 * prefer an authenticated mode such as GCM with a unique IV/nonce per
 * message.
 */

#ifndef AES_H
#define AES_H

#include <stddef.h>
#include <stdint.h>

#define AES_BLOCK_SIZE 16U   /* AES block size in bytes  */
#define AES_KEY_SIZE   16U   /* AES-128 key size in bytes */

/**
 * @brief Encrypt a buffer using AES-128 in ECB mode with PKCS#7 padding.
 *
 * @param plaintext     Input buffer to encrypt.
 * @param plaintextLen  Length of plaintext in bytes.
 * @param key           16-byte AES-128 key.
 * @param out           Output buffer for ciphertext bytes.
 * @param outCapacity   Capacity of out buffer.
 * @param outLen        [out] Number of ciphertext bytes written.
 * @return 0 on success, -1 on invalid arguments or insufficient buffer.
 */
int aes128_encrypt_buffer(const uint8_t *plaintext,
                           size_t        plaintextLen,
                           const uint8_t key[AES_KEY_SIZE],
                           uint8_t      *out,
                           size_t        outCapacity,
                           size_t       *outLen);

/**
 * @brief Decrypt a buffer using AES-128 in ECB mode with PKCS#7 padding.
 *
 * @param ciphertext     Input buffer to decrypt.
 * @param ciphertextLen  Length of ciphertext in bytes (multiple of 16).
 * @param key            16-byte AES-128 key.
 * @param out            Output buffer for recovered plaintext.
 * @param outCapacity    Capacity of out buffer.
 * @param outLen         [out] Number of plaintext bytes written.
 * @return 0 on success, -1 on invalid arguments, bad padding, or
 *         insufficient buffer.
 */
int aes128_decrypt_buffer(const uint8_t *ciphertext,
                           size_t         ciphertextLen,
                           const uint8_t  key[AES_KEY_SIZE],
                           uint8_t       *out,
                           size_t         outCapacity,
                           size_t        *outLen);

/**
 * @brief Encrypt a NUL-terminated string and hex-encode the result.
 *
 * @param plaintext Input NUL-terminated string.
 * @param key       16-byte AES-128 key.
 * @param outHex    Output buffer for hex-encoded ciphertext.
 * @param outHexCap Capacity of outHex buffer.
 * @return 0 on success, -1 on failure.
 */
int aes128_encrypt_to_hex(const char *plaintext,
                           const uint8_t key[AES_KEY_SIZE],
                           char *outHex,
                           size_t outHexCap);

/**
 * @brief Decrypt a hex-encoded ciphertext produced by
 *        aes128_encrypt_to_hex() back into a NUL-terminated string.
 *
 * @param hexCipher  Hex-encoded ciphertext string.
 * @param key        16-byte AES-128 key.
 * @param outPlain   Output buffer for recovered plaintext string.
 * @param outCap     Capacity of outPlain buffer.
 * @return 0 on success, -1 on failure.
 */
int aes128_decrypt_from_hex(const char *hexCipher,
                             const uint8_t key[AES_KEY_SIZE],
                             char *outPlain,
                             size_t outCap);

#endif /* AES_H */
