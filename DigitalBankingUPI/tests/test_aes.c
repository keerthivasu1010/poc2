/**
 * @file test_aes.c
 * @brief Unit tests for the AES-128 module (src/aes.c).
 */

#include <string.h>
#include <CUnit/CUnit.h>
#include "aes.h"
#include "test_runner.h"

/* FIPS-197 Appendix B / C.1 known-answer test vector for AES-128. */
static const uint8_t FIPS197_KEY[AES_KEY_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static const uint8_t FIPS197_PLAINTEXT[AES_BLOCK_SIZE] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

static const uint8_t FIPS197_CIPHERTEXT[AES_BLOCK_SIZE] = {
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
};

static void test_aes_known_vector_single_block(void)
{
    /* Single full block, no padding: encrypt of a 16-byte input that
     * is already block-aligned still gets a full PKCS#7 padding
     * block appended by design, so we test the raw block transform
     * indirectly by decrypting a manually PKCS#7-padded ciphertext
     * built from the known vector to confirm the core cipher matches
     * FIPS-197 -- decrypting the known ciphertext block directly. */
    uint8_t out[AES_BLOCK_SIZE * 2U];
    size_t outLen = 0U;
    uint8_t paddedCipher[AES_BLOCK_SIZE * 2U];

    /* Encrypt 16 bytes of real data followed by a second, fully-padded
     * block (16 bytes of 0x10) so we can isolate and compare the
     * first ciphertext block against the FIPS-197 known answer. */
    memcpy(paddedCipher, FIPS197_CIPHERTEXT, AES_BLOCK_SIZE);

    CU_ASSERT_EQUAL(aes128_encrypt_buffer(FIPS197_PLAINTEXT, AES_BLOCK_SIZE,
                                           FIPS197_KEY, out, sizeof(out), &outLen), 0);
    /* PKCS#7 padding always appends a full block when input length is
     * an exact multiple of the block size, so ciphertext is 2 blocks. */
    CU_ASSERT_EQUAL(outLen, (size_t)(AES_BLOCK_SIZE * 2U));
    CU_ASSERT_EQUAL(memcmp(out, FIPS197_CIPHERTEXT, AES_BLOCK_SIZE), 0);
}

static void test_aes_roundtrip_buffer(void)
{
    const uint8_t key[AES_KEY_SIZE] = {
        0x2bU, 0x7eU, 0x15U, 0x16U, 0x28U, 0xaeU, 0xd2U, 0xa6U,
        0xabU, 0xf7U, 0x15U, 0x88U, 0x09U, 0xcfU, 0x4fU, 0x3cU
    };
    const uint8_t plaintext[] = "alice|bob@digitalbank|500.00|2026-01-01 10:00:00";
    uint8_t cipher[256];
    uint8_t recovered[256];
    size_t cipherLen = 0U;
    size_t recoveredLen = 0U;

    CU_ASSERT_EQUAL(aes128_encrypt_buffer(plaintext, sizeof(plaintext) - 1U, key,
                                           cipher, sizeof(cipher), &cipherLen), 0);
    CU_ASSERT_TRUE(cipherLen >= sizeof(plaintext) - 1U);
    CU_ASSERT_EQUAL(cipherLen % AES_BLOCK_SIZE, 0U);

    CU_ASSERT_EQUAL(aes128_decrypt_buffer(cipher, cipherLen, key,
                                           recovered, sizeof(recovered), &recoveredLen), 0);
    CU_ASSERT_EQUAL(recoveredLen, sizeof(plaintext) - 1U);
    CU_ASSERT_EQUAL(memcmp(recovered, plaintext, recoveredLen), 0);
}

static void test_aes_roundtrip_hex_string(void)
{
    const uint8_t key[AES_KEY_SIZE] = {
        0x2bU, 0x7eU, 0x15U, 0x16U, 0x28U, 0xaeU, 0xd2U, 0xa6U,
        0xabU, 0xf7U, 0x15U, 0x88U, 0x09U, 0xcfU, 0x4fU, 0x3cU
    };
    const char *plaintext = "carol|dave@digitalbank|75.00|2026-02-14 09:30:00";
    char hex[512];
    char recovered[512];

    CU_ASSERT_EQUAL(aes128_encrypt_to_hex(plaintext, key, hex, sizeof(hex)), 0);
    CU_ASSERT_TRUE(strlen(hex) > 0U);
    CU_ASSERT_EQUAL(aes128_decrypt_from_hex(hex, key, recovered, sizeof(recovered)), 0);
    CU_ASSERT_STRING_EQUAL(recovered, plaintext);
}

static void test_aes_empty_plaintext_roundtrip(void)
{
    const uint8_t key[AES_KEY_SIZE] = {0};
    char hex[128];
    char recovered[128];

    CU_ASSERT_EQUAL(aes128_encrypt_to_hex("", key, hex, sizeof(hex)), 0);
    CU_ASSERT_EQUAL(aes128_decrypt_from_hex(hex, key, recovered, sizeof(recovered)), 0);
    CU_ASSERT_STRING_EQUAL(recovered, "");
}

static void test_aes_different_keys_produce_different_ciphertext(void)
{
    const uint8_t key1[AES_KEY_SIZE] = {0x01};
    const uint8_t key2[AES_KEY_SIZE] = {0x02};
    char hex1[128];
    char hex2[128];

    CU_ASSERT_EQUAL(aes128_encrypt_to_hex("same-plaintext", key1, hex1, sizeof(hex1)), 0);
    CU_ASSERT_EQUAL(aes128_encrypt_to_hex("same-plaintext", key2, hex2, sizeof(hex2)), 0);
    CU_ASSERT_STRING_NOT_EQUAL(hex1, hex2);
}

static void test_aes_null_and_invalid_arguments(void)
{
    const uint8_t key[AES_KEY_SIZE] = {0};
    uint8_t out[32];
    size_t outLen = 0U;
    char hexOut[64];

    CU_ASSERT_EQUAL(aes128_encrypt_buffer(NULL, 4U, key, out, sizeof(out), &outLen), -1);
    CU_ASSERT_EQUAL(aes128_encrypt_buffer((const uint8_t *)"abcd", 4U, NULL, out, sizeof(out), &outLen), -1);
    CU_ASSERT_EQUAL(aes128_encrypt_buffer((const uint8_t *)"abcd", 4U, key, NULL, sizeof(out), &outLen), -1);
    CU_ASSERT_EQUAL(aes128_encrypt_buffer((const uint8_t *)"abcd", 4U, key, out, sizeof(out), NULL), -1);

    CU_ASSERT_EQUAL(aes128_decrypt_buffer(NULL, 16U, key, out, sizeof(out), &outLen), -1);
    CU_ASSERT_EQUAL(aes128_encrypt_to_hex(NULL, key, hexOut, sizeof(hexOut)), -1);
    CU_ASSERT_EQUAL(aes128_decrypt_from_hex(NULL, key, (char *)out, sizeof(out)), -1);
}

static void test_aes_insufficient_output_buffer(void)
{
    const uint8_t key[AES_KEY_SIZE] = {0};
    uint8_t tinyOut[4];
    size_t outLen = 0U;

    CU_ASSERT_EQUAL(aes128_encrypt_buffer((const uint8_t *)"0123456789abcdef", 16U, key,
                                           tinyOut, sizeof(tinyOut), &outLen), -1);
}

static void test_aes_corrupted_ciphertext_rejected(void)
{
    const uint8_t key[AES_KEY_SIZE] = {0x2bU, 0x7eU, 0x15U, 0x16U};
    char hex[128];
    char recovered[128];

    CU_ASSERT_EQUAL(aes128_encrypt_to_hex("integrity-check", key, hex, sizeof(hex)), 0);
    /* Flip a hex digit to corrupt the padding/data. */
    hex[0] = (hex[0] == 'a') ? 'b' : 'a';
    /* Corrupted ciphertext should either fail to decrypt (bad
     * padding) or, in the unlikely case padding happens to still be
     * well-formed, must not reproduce the original plaintext. */
    if (aes128_decrypt_from_hex(hex, key, recovered, sizeof(recovered)) == 0)
    {
        CU_ASSERT_STRING_NOT_EQUAL(recovered, "integrity-check");
    }
}

CU_pSuite test_aes_suite_create(void)
{
    CU_pSuite suite = CU_add_suite("aes", NULL, NULL);
    if (suite == NULL) { return NULL; }

    CU_add_test(suite, "FIPS-197 known vector (first block)", test_aes_known_vector_single_block);
    CU_add_test(suite, "buffer round-trip", test_aes_roundtrip_buffer);
    CU_add_test(suite, "hex-string round-trip", test_aes_roundtrip_hex_string);
    CU_add_test(suite, "empty plaintext round-trip", test_aes_empty_plaintext_roundtrip);
    CU_add_test(suite, "different keys diverge", test_aes_different_keys_produce_different_ciphertext);
    CU_add_test(suite, "NULL/invalid arguments", test_aes_null_and_invalid_arguments);
    CU_add_test(suite, "insufficient output buffer", test_aes_insufficient_output_buffer);
    CU_add_test(suite, "corrupted ciphertext rejected or mismatched", test_aes_corrupted_ciphertext_rejected);

    return suite;
}
