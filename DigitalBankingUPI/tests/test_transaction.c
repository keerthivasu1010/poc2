/**
 * @file test_transaction.c
 * @brief Unit tests for the transaction module (src/transaction.c,
 *        src/history.c).
 */

#include <string.h>
#include <CUnit/CUnit.h>
#include "transaction.h"
#include "storage.h"
#include "test_common.h"
#include "test_runner.h"

static int transaction_suite_init(void)
{
    return test_sandbox_enter("transaction");
}

static int transaction_suite_cleanup(void)
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

/* --- upi_is_valid_format --- */

static void test_upi_valid_formats(void)
{
    CU_ASSERT_EQUAL(upi_is_valid_format("alice@digitalbank"), 1);
    CU_ASSERT_EQUAL(upi_is_valid_format("bob.smith@okhdfcbank"), 1);
    CU_ASSERT_EQUAL(upi_is_valid_format("user_99@ybl"), 1);
    CU_ASSERT_EQUAL(upi_is_valid_format("a1-2@paytm"), 1);
}

static void test_upi_invalid_formats(void)
{
    CU_ASSERT_EQUAL(upi_is_valid_format(NULL), 0);
    CU_ASSERT_EQUAL(upi_is_valid_format(""), 0);
    CU_ASSERT_EQUAL(upi_is_valid_format("noatsign"), 0);
    CU_ASSERT_EQUAL(upi_is_valid_format("@digitalbank"), 0);
    CU_ASSERT_EQUAL(upi_is_valid_format("alice@"), 0);
    CU_ASSERT_EQUAL(upi_is_valid_format("a@b@c"), 0);
    CU_ASSERT_EQUAL(upi_is_valid_format("bad space@digitalbank"), 0);
    CU_ASSERT_EQUAL(upi_is_valid_format("ab"), 0);
}

/* --- transaction_transfer --- */

static void test_transfer_local_to_local_success(void)
{
    User sender;
    User receiver;

    register_local_user("txfrom1", 500.0);
    register_local_user("txto1", 100.0);

    CU_ASSERT_EQUAL(transaction_transfer("txfrom1", "txto1@digitalbank", 150.0), 0);

    CU_ASSERT_EQUAL(storage_find_user("txfrom1", &sender), 1);
    CU_ASSERT_EQUAL(storage_find_user("txto1", &receiver), 1);
    CU_ASSERT_DOUBLE_EQUAL(sender.balance, 350.0, 0.001);
    CU_ASSERT_DOUBLE_EQUAL(receiver.balance, 250.0, 0.001);
}

static void test_transfer_to_external_upi_debits_sender_only(void)
{
    User sender;

    register_local_user("txfrom2", 300.0);

    CU_ASSERT_EQUAL(transaction_transfer("txfrom2", "merchant@okhdfcbank", 50.0), 0);

    CU_ASSERT_EQUAL(storage_find_user("txfrom2", &sender), 1);
    CU_ASSERT_DOUBLE_EQUAL(sender.balance, 250.0, 0.001);
}

static void test_transfer_invalid_arguments(void)
{
    register_local_user("txfrom3", 100.0);
    CU_ASSERT_EQUAL(transaction_transfer(NULL, "x@digitalbank", 10.0), -1);
    CU_ASSERT_EQUAL(transaction_transfer("txfrom3", NULL, 10.0), -1);
    CU_ASSERT_EQUAL(transaction_transfer("txfrom3", "x@digitalbank", 0.0), -1);
    CU_ASSERT_EQUAL(transaction_transfer("txfrom3", "x@digitalbank", -5.0), -1);
}

static void test_transfer_malformed_upi_rejected(void)
{
    register_local_user("txfrom4", 100.0);
    CU_ASSERT_EQUAL(transaction_transfer("txfrom4", "not-a-upi", 10.0), -6);
}

static void test_transfer_unknown_sender_rejected(void)
{
    CU_ASSERT_EQUAL(transaction_transfer("ghost_sender_xyz", "someone@digitalbank", 10.0), -2);
}

static void test_transfer_self_transfer_rejected(void)
{
    register_local_user("txself1", 100.0);
    CU_ASSERT_EQUAL(transaction_transfer("txself1", "txself1@digitalbank", 10.0), -1);
}

static void test_transfer_insufficient_balance_rejected(void)
{
    User sender;

    register_local_user("txpoor1", 20.0);
    register_local_user("txrich1", 20.0);

    CU_ASSERT_EQUAL(transaction_transfer("txpoor1", "txrich1@digitalbank", 100.0), -4);
    CU_ASSERT_EQUAL(storage_find_user("txpoor1", &sender), 1);
    CU_ASSERT_DOUBLE_EQUAL(sender.balance, 20.0, 0.001);
}

static void test_transfer_exact_balance_allowed(void)
{
    User sender;

    register_local_user("txexact1", 75.0);
    register_local_user("txexactto1", 0.0);

    CU_ASSERT_EQUAL(transaction_transfer("txexact1", "txexactto1@digitalbank", 75.0), 0);
    CU_ASSERT_EQUAL(storage_find_user("txexact1", &sender), 1);
    CU_ASSERT_DOUBLE_EQUAL(sender.balance, 0.0, 0.001);
}

/* --- transaction_show_history --- */

static void test_show_history_null_username(void)
{
    CU_ASSERT_EQUAL(transaction_show_history(NULL), -1);
}

static void test_show_history_counts_matching_transactions(void)
{
    int visited;

    register_local_user("histuser1", 200.0);
    register_local_user("histuser2", 0.0);

    CU_ASSERT_EQUAL(transaction_transfer("histuser1", "histuser2@digitalbank", 10.0), 0);
    CU_ASSERT_EQUAL(transaction_transfer("histuser1", "histuser2@digitalbank", 5.0), 0);

    visited = transaction_show_history("histuser1");
    CU_ASSERT_TRUE(visited >= 2);

    visited = transaction_show_history("user_with_no_history_xyz");
    CU_ASSERT_EQUAL(visited, 0);
}

CU_pSuite test_transaction_suite_create(void)
{
    CU_pSuite suite = CU_add_suite("transaction", transaction_suite_init, transaction_suite_cleanup);
    if (suite == NULL) { return NULL; }

    CU_add_test(suite, "valid UPI formats accepted", test_upi_valid_formats);
    CU_add_test(suite, "invalid UPI formats rejected", test_upi_invalid_formats);
    CU_add_test(suite, "local-to-local transfer success", test_transfer_local_to_local_success);
    CU_add_test(suite, "transfer to external UPI debits sender only", test_transfer_to_external_upi_debits_sender_only);
    CU_add_test(suite, "invalid arguments rejected", test_transfer_invalid_arguments);
    CU_add_test(suite, "malformed UPI ID rejected", test_transfer_malformed_upi_rejected);
    CU_add_test(suite, "unknown sender rejected", test_transfer_unknown_sender_rejected);
    CU_add_test(suite, "self-transfer rejected", test_transfer_self_transfer_rejected);
    CU_add_test(suite, "insufficient balance rejected", test_transfer_insufficient_balance_rejected);
    CU_add_test(suite, "exact-balance transfer allowed", test_transfer_exact_balance_allowed);
    CU_add_test(suite, "history: NULL username", test_show_history_null_username);
    CU_add_test(suite, "history: counts matching transactions", test_show_history_counts_matching_transactions);

    return suite;
}
