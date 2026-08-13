/**
 * @file test_integrity.c
 * @brief Unit tests for the integrity module (src/integrity.c).
 */

#include <stdio.h>
#include <string.h>
#include <CUnit/CUnit.h>
#include "integrity.h"
#include "transaction.h"
#include "storage.h"
#include "test_common.h"
#include "test_runner.h"

static int integrity_suite_init(void)
{
    return test_sandbox_enter("integrity");
}

static int integrity_suite_cleanup(void)
{
    test_sandbox_leave();
    return 0;
}

static void register_local_user(const char *username, double balance)
{
    User u;
    memset(&u, 0, sizeof(u));
    strncpy(u.username, username, sizeof(u.username) - 1U);
    (void)snprintf(u.upiID, sizeof(u.upiID), "%s@digitalbank", username);
    strncpy(u.passwordHash, "deadbeef", sizeof(u.passwordHash) - 1U);
    u.balance = balance;
    CU_ASSERT_EQUAL(storage_add_user(&u), 0);
}

static void test_integrity_compute_hash_deterministic(void)
{
    char hash1[65];
    char hash2[65];

    CU_ASSERT_EQUAL(integrity_compute_hash("alice", "bob@digitalbank", 100.0,
                                            "2026-01-01 10:00:00", hash1), 0);
    CU_ASSERT_EQUAL(integrity_compute_hash("alice", "bob@digitalbank", 100.0,
                                            "2026-01-01 10:00:00", hash2), 0);
    CU_ASSERT_STRING_EQUAL(hash1, hash2);
    CU_ASSERT_EQUAL(strlen(hash1), 64U);
}

static void test_integrity_compute_hash_sensitive_to_amount(void)
{
    char hash1[65];
    char hash2[65];

    CU_ASSERT_EQUAL(integrity_compute_hash("alice", "bob@digitalbank", 100.0,
                                            "2026-01-01 10:00:00", hash1), 0);
    CU_ASSERT_EQUAL(integrity_compute_hash("alice", "bob@digitalbank", 100.01,
                                            "2026-01-01 10:00:00", hash2), 0);
    CU_ASSERT_STRING_NOT_EQUAL(hash1, hash2);
}

static void test_integrity_compute_hash_null_arguments(void)
{
    char hash[65];
    CU_ASSERT_EQUAL(integrity_compute_hash(NULL, "bob@digitalbank", 1.0, "ts", hash), -1);
    CU_ASSERT_EQUAL(integrity_compute_hash("alice", NULL, 1.0, "ts", hash), -1);
    CU_ASSERT_EQUAL(integrity_compute_hash("alice", "bob@digitalbank", 1.0, NULL, hash), -1);
    CU_ASSERT_EQUAL(integrity_compute_hash("alice", "bob@digitalbank", 1.0, "ts", NULL), -1);
}

static void test_integrity_verify_null_username(void)
{
    CU_ASSERT_EQUAL(integrity_verify_user_transactions(NULL), -1);
}

static void test_integrity_verify_untampered_transaction(void)
{
    int checked;

    register_local_user("intuser1", 500.0);
    register_local_user("intuser2", 0.0);

    CU_ASSERT_EQUAL(transaction_transfer("intuser1", "intuser2@digitalbank", 25.0), 0);

    checked = integrity_verify_user_transactions("intuser1");
    CU_ASSERT_TRUE(checked >= 1);
}

static void test_integrity_verify_no_transactions(void)
{
    CU_ASSERT_EQUAL(integrity_verify_user_transactions("user_with_no_txns_xyz"), 0);
}

static void test_integrity_verify_tampered_transaction(void)
{
    FILE *fp;
    int checked;

    register_local_user("intuser3", 200.0);

    fp = fopen("database/transactions.dat", "a");
    CU_ASSERT_PTR_NOT_NULL(fp);
    if (fp != NULL)
    {
        fprintf(fp, "intuser3|intuser4@digitalbank|10.00|2026-01-01 10:00:00|zz|deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n");
        (void)fclose(fp);
    }

    checked = integrity_verify_user_transactions("intuser3");
    CU_ASSERT_TRUE(checked >= 1);
}

CU_pSuite test_integrity_suite_create(void)
{
    CU_pSuite suite = CU_add_suite("integrity", integrity_suite_init, integrity_suite_cleanup);
    if (suite == NULL) { return NULL; }

    CU_add_test(suite, "compute_hash deterministic", test_integrity_compute_hash_deterministic);
    CU_add_test(suite, "compute_hash sensitive to amount", test_integrity_compute_hash_sensitive_to_amount);
    CU_add_test(suite, "compute_hash NULL arguments", test_integrity_compute_hash_null_arguments);
    CU_add_test(suite, "verify: NULL username", test_integrity_verify_null_username);
    CU_add_test(suite, "verify: untampered transaction", test_integrity_verify_untampered_transaction);
    CU_add_test(suite, "verify: no transactions", test_integrity_verify_no_transactions);
    CU_add_test(suite, "verify: tampered transaction", test_integrity_verify_tampered_transaction);

    return suite;
}
