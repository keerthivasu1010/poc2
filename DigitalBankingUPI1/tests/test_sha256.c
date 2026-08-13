/**
 * @file test_sha256.c
 * @brief Unit tests for the SHA-256 module (src/sha256.c).
 */

#include <string.h>
#include <CUnit/CUnit.h>
#include "sha256.h"
#include "test_runner.h"

/* NIST/FIPS 180-4 known-answer test vectors. */
static void test_sha256_empty_string(void)
{
    char hex[SHA256_HEX_BUF];
    CU_ASSERT_EQUAL(sha256_hash_string("", hex), 0);
    CU_ASSERT_STRING_EQUAL(hex,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

static void test_sha256_abc(void)
{
    char hex[SHA256_HEX_BUF];
    CU_ASSERT_EQUAL(sha256_hash_string("abc", hex), 0);
    CU_ASSERT_STRING_EQUAL(hex,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

static void test_sha256_long_message(void)
{
    char hex[SHA256_HEX_BUF];
    const char *msg =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    CU_ASSERT_EQUAL(sha256_hash_string(msg, hex), 0);
    CU_ASSERT_STRING_EQUAL(hex,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

static void test_sha256_deterministic(void)
{
    char hex1[SHA256_HEX_BUF];
    char hex2[SHA256_HEX_BUF];
    CU_ASSERT_EQUAL(sha256_hash_string("Password1:1234", hex1), 0);
    CU_ASSERT_EQUAL(sha256_hash_string("Password1:1234", hex2), 0);
    CU_ASSERT_STRING_EQUAL(hex1, hex2);
    CU_ASSERT_EQUAL(strlen(hex1), (size_t)SHA256_HEX_LEN);
}

static void test_sha256_avalanche(void)
{
    char hex1[SHA256_HEX_BUF];
    char hex2[SHA256_HEX_BUF];
    CU_ASSERT_EQUAL(sha256_hash_string("Password1:1234", hex1), 0);
    CU_ASSERT_EQUAL(sha256_hash_string("Password1:1235", hex2), 0);
    CU_ASSERT_STRING_NOT_EQUAL(hex1, hex2);
}

static void test_sha256_null_input(void)
{
    char hex[SHA256_HEX_BUF];
    CU_ASSERT_EQUAL(sha256_hash_string(NULL, hex), -1);
    CU_ASSERT_EQUAL(sha256_hash_string("abc", NULL), -1);
    CU_ASSERT_EQUAL(sha256_hash_buffer(NULL, 3U, hex), -1);
    CU_ASSERT_EQUAL(sha256_hash_buffer((const uint8_t *)"abc", 3U, NULL), -1);
}

static void test_sha256_buffer_vs_string(void)
{
    char hex1[SHA256_HEX_BUF];
    char hex2[SHA256_HEX_BUF];
    const char *msg = "digital-banking-upi";
    CU_ASSERT_EQUAL(sha256_hash_string(msg, hex1), 0);
    CU_ASSERT_EQUAL(sha256_hash_buffer((const uint8_t *)msg, strlen(msg), hex2), 0);
    CU_ASSERT_STRING_EQUAL(hex1, hex2);
}

static void test_sha256_incremental_matches_oneshot(void)
{
    SHA256_CTX ctx;
    uint8_t digest[SHA256_BLOCK_SIZE];
    char hexIncremental[SHA256_HEX_BUF];
    char hexOneShot[SHA256_HEX_BUF];
    size_t i;
    const char *msg = "abc";

    sha256_init(&ctx);
    for (i = 0U; i < strlen(msg); i++)
    {
        sha256_update(&ctx, (const uint8_t *)&msg[i], 1U);
    }
    sha256_final(&ctx, digest);

    for (i = 0U; i < SHA256_BLOCK_SIZE; i++)
    {
        (void)snprintf(&hexIncremental[i * 2U], 3U, "%02x", digest[i]);
    }

    CU_ASSERT_EQUAL(sha256_hash_string(msg, hexOneShot), 0);
    CU_ASSERT_STRING_EQUAL(hexIncremental, hexOneShot);
}

CU_pSuite test_sha256_suite_create(void)
{
    CU_pSuite suite = CU_add_suite("sha256", NULL, NULL);
    if (suite == NULL) { return NULL; }

    CU_add_test(suite, "empty string vector", test_sha256_empty_string);
    CU_add_test(suite, "\"abc\" vector", test_sha256_abc);
    CU_add_test(suite, "long message vector", test_sha256_long_message);
    CU_add_test(suite, "deterministic output", test_sha256_deterministic);
    CU_add_test(suite, "avalanche effect", test_sha256_avalanche);
    CU_add_test(suite, "NULL argument handling", test_sha256_null_input);
    CU_add_test(suite, "buffer vs string API parity", test_sha256_buffer_vs_string);
    CU_add_test(suite, "incremental equals one-shot", test_sha256_incremental_matches_oneshot);

    return suite;
}
