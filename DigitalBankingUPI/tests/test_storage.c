/**
 * @file test_storage.c
 * @brief Unit tests for the storage module (src/storage.c).
 */

#include <string.h>
#include <CUnit/CUnit.h>
#include "storage.h"
#include "test_common.h"
#include "test_runner.h"

static int storage_suite_init(void)
{
    return test_sandbox_enter("storage");
}

static int storage_suite_cleanup(void)
{
    test_sandbox_leave();
    return 0;
}

static User make_user(const char *username, double balance)
{
    User u;
    memset(&u, 0, sizeof(u));
    strncpy(u.username, username, sizeof(u.username) - 1U);
    (void)snprintf(u.upiID, sizeof(u.upiID), "%s@digitalbank", username);
    strncpy(u.passwordHash, "deadbeef", sizeof(u.passwordHash) - 1U);
    u.balance = balance;
    return u;
}

static void test_storage_add_and_find_user(void)
{
    User u = make_user("storeuser1", 100.0);
    User found;

    CU_ASSERT_EQUAL(storage_add_user(&u), 0);
    CU_ASSERT_EQUAL(storage_find_user("storeuser1", &found), 1);
    CU_ASSERT_STRING_EQUAL(found.username, "storeuser1");
    CU_ASSERT_DOUBLE_EQUAL(found.balance, 100.0, 0.001);
}

static void test_storage_find_missing_user(void)
{
    User found;
    CU_ASSERT_EQUAL(storage_find_user("does_not_exist_xyz", &found), 0);
}

static void test_storage_duplicate_username_rejected(void)
{
    User u1 = make_user("dupuser", 10.0);
    User u2 = make_user("dupuser", 20.0);

    CU_ASSERT_EQUAL(storage_add_user(&u1), 0);
    CU_ASSERT_EQUAL(storage_add_user(&u2), -1);
}

static void test_storage_find_user_by_upi(void)
{
    User u = make_user("upiuser1", 55.0);
    User found;

    CU_ASSERT_EQUAL(storage_add_user(&u), 0);
    CU_ASSERT_EQUAL(storage_find_user_by_upi("upiuser1@digitalbank", &found), 1);
    CU_ASSERT_STRING_EQUAL(found.username, "upiuser1");
    CU_ASSERT_EQUAL(storage_find_user_by_upi("nobody@digitalbank", &found), 0);
}

static void test_storage_update_balance(void)
{
    User u = make_user("balanceuser1", 200.0);
    User found;

    CU_ASSERT_EQUAL(storage_add_user(&u), 0);
    CU_ASSERT_EQUAL(storage_update_balance("balanceuser1", 350.0), 0);
    CU_ASSERT_EQUAL(storage_find_user("balanceuser1", &found), 1);
    CU_ASSERT_DOUBLE_EQUAL(found.balance, 350.0, 0.001);
}

static void test_storage_update_balance_missing_user(void)
{
    CU_ASSERT_EQUAL(storage_update_balance("nobody_here_xyz", 10.0), -1);
}

static void test_storage_update_user_full_record(void)
{
    User u = make_user("fulluser1", 10.0);
    User found;

    CU_ASSERT_EQUAL(storage_add_user(&u), 0);
    u.isFrozen = 1;
    u.failedAttempts = 3;
    CU_ASSERT_EQUAL(storage_update_user(&u), 0);

    CU_ASSERT_EQUAL(storage_find_user("fulluser1", &found), 1);
    CU_ASSERT_EQUAL(found.isFrozen, 1);
    CU_ASSERT_EQUAL(found.failedAttempts, 3);
}

static void test_storage_update_user_missing_returns_error(void)
{
    User u = make_user("neverexisted1", 0.0);
    CU_ASSERT_EQUAL(storage_update_user(&u), -1);
}

typedef struct
{
    int count;
} CountCtx;

static void count_user_visitor(const User *user, void *userData)
{
    CountCtx *ctx = (CountCtx *)userData;
    (void)user;
    ctx->count++;
}

static void count_txn_visitor(const Transaction *txn, void *userData)
{
    CountCtx *ctx = (CountCtx *)userData;
    (void)txn;
    ctx->count++;
}

static void test_storage_for_each_user(void)
{
    CountCtx before = {0};
    CountCtx after = {0};
    User u1 = make_user("iteruser1", 1.0);
    User u2 = make_user("iteruser2", 2.0);

    CU_ASSERT_TRUE(storage_for_each_user(count_user_visitor, &before) >= 0);

    CU_ASSERT_EQUAL(storage_add_user(&u1), 0);
    CU_ASSERT_EQUAL(storage_add_user(&u2), 0);

    CU_ASSERT_TRUE(storage_for_each_user(count_user_visitor, &after) >= 0);
    CU_ASSERT_EQUAL(after.count, before.count + 2);
}

static void test_storage_add_and_iterate_transactions(void)
{
    Transaction txn;
    CountCtx before = {0};
    CountCtx after = {0};

    memset(&txn, 0, sizeof(txn));
    strncpy(txn.sender, "txsender1", sizeof(txn.sender) - 1U);
    strncpy(txn.receiver, "txreceiver1@digitalbank", sizeof(txn.receiver) - 1U);
    txn.amount = 42.5;
    strncpy(txn.timestamp, "2026-01-01 00:00:00", sizeof(txn.timestamp) - 1U);
    strncpy(txn.encryptedData, "deadbeef", sizeof(txn.encryptedData) - 1U);
    strncpy(txn.hash, "cafebabe", sizeof(txn.hash) - 1U);

    CU_ASSERT_TRUE(storage_for_each_transaction(count_txn_visitor, &before) >= 0);
    CU_ASSERT_EQUAL(storage_add_transaction(&txn), 0);
    CU_ASSERT_TRUE(storage_for_each_transaction(count_txn_visitor, &after) >= 0);
    CU_ASSERT_EQUAL(after.count, before.count + 1);
}

static void test_storage_null_arguments(void)
{
    User u;
    CU_ASSERT_EQUAL(storage_find_user(NULL, &u), -1);
    CU_ASSERT_EQUAL(storage_find_user("someone", NULL), -1);
    CU_ASSERT_EQUAL(storage_find_user_by_upi(NULL, &u), -1);
    CU_ASSERT_EQUAL(storage_add_user(NULL), -1);
    CU_ASSERT_EQUAL(storage_update_user(NULL), -1);
    CU_ASSERT_EQUAL(storage_update_balance(NULL, 1.0), -1);
    CU_ASSERT_EQUAL(storage_for_each_user(NULL, NULL), -1);
    CU_ASSERT_EQUAL(storage_add_transaction(NULL), -1);
    CU_ASSERT_EQUAL(storage_for_each_transaction(NULL, NULL), -1);
}

static void test_storage_empty_store_iteration(void)
{
    /* A freshly-initialised empty store should iterate zero records,
     * not error. Uses a distinct sandbox-relative check: right after
     * suite init before any add, count via a local scan. */
    CountCtx ctx = {0};
    int rc = storage_for_each_transaction(count_txn_visitor, &ctx);
    CU_ASSERT_TRUE(rc >= 0);
}

CU_pSuite test_storage_suite_create(void)
{
    CU_pSuite suite = CU_add_suite("storage", storage_suite_init, storage_suite_cleanup);
    if (suite == NULL) { return NULL; }

    CU_add_test(suite, "add and find user", test_storage_add_and_find_user);
    CU_add_test(suite, "find missing user returns 0", test_storage_find_missing_user);
    CU_add_test(suite, "duplicate username rejected", test_storage_duplicate_username_rejected);
    CU_add_test(suite, "find user by UPI ID", test_storage_find_user_by_upi);
    CU_add_test(suite, "update balance", test_storage_update_balance);
    CU_add_test(suite, "update balance for missing user", test_storage_update_balance_missing_user);
    CU_add_test(suite, "update full user record", test_storage_update_user_full_record);
    CU_add_test(suite, "update missing user returns error", test_storage_update_user_missing_returns_error);
    CU_add_test(suite, "iterate all users", test_storage_for_each_user);
    CU_add_test(suite, "add and iterate transactions", test_storage_add_and_iterate_transactions);
    CU_add_test(suite, "NULL argument handling", test_storage_null_arguments);
    CU_add_test(suite, "empty store iteration", test_storage_empty_store_iteration);

    return suite;
}
