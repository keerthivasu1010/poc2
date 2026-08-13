/**
 * @file test_crypto.c
 * @brief Standalone unit tests (DIGI-10) for the SHA-256 and AES-128
 *        modules using known-answer test vectors, plus a small
 *        integration test (DIGI-11) exercising the storage +
 *        transaction + integrity pipeline end to end.
 *
 * Build: gcc -std=c99 -Wall -Wextra -Iinclude src/sha256.c src/aes.c \
 *            src/storage.c src/audit.c src/transaction.c \
 *            src/integrity.c test/test_crypto.c -o test_crypto
 * Run:   ./test_crypto
 */

#include <stdio.h>
#include <string.h>
#include "sha256.h"
#include "aes.h"
#include "storage.h"
#include "transaction.h"
#include "integrity.h"

static int g_failures = 0;

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            printf("  [FAIL] %s\n", msg); \
            g_failures++; \
        } else { \
            printf("  [ OK ] %s\n", msg); \
        } \
    } while (0)

static void test_sha256_known_vectors(void)
{
    char out[SHA256_HEX_BUF];

    printf("\n== SHA-256 known-answer tests ==\n");

    (void)sha256_hash_string("", out);
    CHECK(strcmp(out, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0,
          "SHA-256(\"\") matches NIST empty-string vector");

    (void)sha256_hash_string("abc", out);
    CHECK(strcmp(out, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
          "SHA-256(\"abc\") matches NIST test vector");

    (void)sha256_hash_string(
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", out);
    CHECK(strcmp(out, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0,
          "SHA-256 multi-block message matches NIST test vector");
}

static void test_sha256_determinism_and_avalanche(void)
{
    char h1[SHA256_HEX_BUF];
    char h2[SHA256_HEX_BUF];

    printf("\n== SHA-256 determinism / avalanche ==\n");

    (void)sha256_hash_string("password1:1234", h1);
    (void)sha256_hash_string("password1:1234", h2);
    CHECK(strcmp(h1, h2) == 0, "Same input always produces same hash");

    (void)sha256_hash_string("password1:1235", h2);
    CHECK(strcmp(h1, h2) != 0, "Different input produces different hash");
}

static void test_aes_roundtrip(void)
{
    const uint8_t key[AES_KEY_SIZE] = {
        0x2bU, 0x7eU, 0x15U, 0x16U, 0x28U, 0xaeU, 0xd2U, 0xa6U,
        0xabU, 0xf7U, 0x15U, 0x88U, 0x09U, 0xcfU, 0x4fU, 0x3cU
    };
    char cipherHex[256];
    char recovered[128];

    printf("\n== AES-128 round-trip tests ==\n");

    CHECK(aes128_encrypt_to_hex("alice|bob|150.50|2026-07-29 10:00:00", key,
                                 cipherHex, sizeof(cipherHex)) == 0,
          "Encrypt transaction payload succeeds");

    CHECK(aes128_decrypt_from_hex(cipherHex, key, recovered, sizeof(recovered)) == 0,
          "Decrypt ciphertext succeeds");

    CHECK(strcmp(recovered, "alice|bob|150.50|2026-07-29 10:00:00") == 0,
          "Decrypted payload matches original plaintext");

    /* Empty-string edge case: must still pad to one full block. */
    CHECK(aes128_encrypt_to_hex("", key, cipherHex, sizeof(cipherHex)) == 0,
          "Encrypt empty string succeeds");
    CHECK(aes128_decrypt_from_hex(cipherHex, key, recovered, sizeof(recovered)) == 0,
          "Decrypt empty-string ciphertext succeeds");
    CHECK(strcmp(recovered, "") == 0, "Decrypted empty string matches");
}

static void test_aes_known_vector(void)
{
    /* FIPS-197 Appendix B / C.1 AES-128 single-block known-answer test. */
    const uint8_t key[AES_KEY_SIZE] = {
        0x00U,0x01U,0x02U,0x03U,0x04U,0x05U,0x06U,0x07U,
        0x08U,0x09U,0x0aU,0x0bU,0x0cU,0x0dU,0x0eU,0x0fU
    };
    const uint8_t plaintext[16] = {
        0x00U,0x11U,0x22U,0x33U,0x44U,0x55U,0x66U,0x77U,
        0x88U,0x99U,0xaaU,0xbbU,0xccU,0xddU,0xeeU,0xffU
    };
    const uint8_t expected[16] = {
        0x69U,0xc4U,0xe0U,0xd8U,0x6aU,0x7bU,0x04U,0x30U,
        0xd8U,0xcdU,0xb7U,0x80U,0x70U,0xb4U,0xc5U,0x5aU
    };
    uint8_t out[32];
    size_t outLen = 0U;
    uint8_t decrypted[32];
    size_t decLen = 0U;

    printf("\n== AES-128 FIPS-197 known-answer test ==\n");

    CHECK(aes128_encrypt_buffer(plaintext, sizeof(plaintext), key, out, sizeof(out), &outLen) == 0,
          "Encrypt fixed 16-byte block succeeds");
    /* First 16 bytes are the real ciphertext block; the remaining 16
     * are the PKCS#7 padding block added because the plaintext
     * length is an exact multiple of the block size. */
    CHECK(memcmp(out, expected, 16U) == 0,
          "Ciphertext matches FIPS-197 known-answer vector");

    CHECK(aes128_decrypt_buffer(out, outLen, key, decrypted, sizeof(decrypted), &decLen) == 0,
          "Decrypt recovers original length");
    CHECK((decLen == 16U) && (memcmp(decrypted, plaintext, 16U) == 0),
          "Decrypted plaintext matches original");
}

static void test_storage_and_integrity_integration(void)
{
    User u1;
    User u2;
    int rc;

    printf("\n== Integration test: storage + transaction + integrity ==\n");

    CHECK(storage_init() == 0, "storage_init succeeds");

    memset(&u1, 0, sizeof(u1));
    strncpy(u1.username, "testuser1", sizeof(u1.username) - 1U);
    u1.username[sizeof(u1.username) - 1U] = '\0';
    strncpy(u1.passwordHash, "0000000000000000000000000000000000000000000000000000000000000",
            sizeof(u1.passwordHash) - 1U);
    u1.passwordHash[sizeof(u1.passwordHash) - 1U] = '\0';
    strncpy(u1.upiID, "testuser1@digitalbank", sizeof(u1.upiID) - 1U);
    u1.upiID[sizeof(u1.upiID) - 1U] = '\0';
    u1.balance = 500.0;
    u1.isAdmin = 0;
    u1.isFrozen = 0;
    u1.failedAttempts = 0;
    u1.lockedUntilEpoch = 0L;

    u2 = u1;
    strncpy(u2.username, "testuser2", sizeof(u2.username) - 1U);
    u2.username[sizeof(u2.username) - 1U] = '\0';
    strncpy(u2.upiID, "testuser2@digitalbank", sizeof(u2.upiID) - 1U);
    u2.upiID[sizeof(u2.upiID) - 1U] = '\0';
    u2.balance = 100.0;

    /* Best-effort setup; ignore duplicate-user errors on repeated runs. */
    (void)storage_add_user(&u1);
    (void)storage_add_user(&u2);

    rc = transaction_transfer("testuser1", "testuser2@digitalbank", 50.0);
    CHECK(rc == 0, "transaction_transfer succeeds for valid transfer");

    rc = transaction_transfer("testuser1", "testuser2@digitalbank", -5.0);
    CHECK(rc == -1, "transaction_transfer rejects non-positive amount");

    rc = transaction_transfer("nosuchuser", "testuser2@digitalbank", 5.0);
    CHECK(rc == -2, "transaction_transfer rejects unknown sender");

    rc = transaction_transfer("testuser1", "nosuchuser@digitalbank", 5.0);
    CHECK(rc == 0, "transaction_transfer allows external/unregistered UPI ID");

    rc = transaction_transfer("testuser1", "testuser2@digitalbank", 100000.0);
    CHECK(rc == -4, "transaction_transfer rejects insufficient balance");

    rc = transaction_transfer("testuser1", "not-a-upi-id", 5.0);
    CHECK(rc == -6, "transaction_transfer rejects malformed UPI ID");

    rc = integrity_verify_user_transactions("testuser1");
    CHECK(rc >= 1, "integrity_verify_user_transactions finds at least one record");
}

int main(void)
{
    printf("===========================================\n");
    printf(" Digital Banking Platform - Unit/Integration Tests\n");
    printf("===========================================\n");

    test_sha256_known_vectors();
    test_sha256_determinism_and_avalanche();
    test_aes_roundtrip();
    test_aes_known_vector();
    test_storage_and_integrity_integration();

    printf("\n===========================================\n");
    if (g_failures == 0)
    {
        printf(" ALL TESTS PASSED\n");
    }
    else
    {
        printf(" %d TEST(S) FAILED\n", g_failures);
    }
    printf("===========================================\n");

    return (g_failures == 0) ? 0 : 1;
}
