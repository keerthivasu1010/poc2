/**
 * @file test_account.c
 * @brief Unit tests for the account module (src/account.c).
 */

#include <string.h>
#include <CUnit/CUnit.h>
#include "account.h"
#include "auth.h"
#include "storage.h"
#include "sha256.h"
#include "test_common.h"
#include "test_runner.h"

static int account_suite_init(void)
{
    return test_sandbox_enter("account");
}

static int account_suite_cleanup(void)
{
    test_sandbox_leave();
    return 0;
}

static Session register_and_login(const char *username)
{
    Session session;
    char script[256];

    memset(&session, 0, sizeof(session));

    (void)snprintf(script, sizeof(script), "%s\nGoodPass1\n1234\n", username);
    CU_ASSERT_EQUAL(test_feed_stdin(script), 0);
    CU_ASSERT_EQUAL(registration_register(), 0);
    test_restore_stdin();

    CU_ASSERT_EQUAL(test_feed_stdin(script), 0);
    CU_ASSERT_EQUAL(login_authenticate(&session), 0);
    test_restore_stdin();

    return session;
}

static void test_change_credentials_success(void)
{
    Session session = register_and_login("acctuser1");
    User found;
    char expectedHash[65];

    CU_ASSERT_EQUAL(test_feed_stdin("GoodPass1\n1234\nNewPass2\n5678\n"), 0);
    CU_ASSERT_EQUAL(account_change_credentials(&session), 0);
    test_restore_stdin();

    CU_ASSERT_EQUAL(storage_find_user("acctuser1", &found), 1);
    CU_ASSERT_EQUAL(sha256_hash_string("NewPass2:5678", expectedHash), 0);
    CU_ASSERT_STRING_EQUAL(found.passwordHash, expectedHash);
}

static void test_change_credentials_wrong_current_rejected(void)
{
    Session session = register_and_login("acctuser2");

    CU_ASSERT_EQUAL(test_feed_stdin("WrongPass1\n1234\nNewPass2\n5678\n"), 0);
    CU_ASSERT_EQUAL(account_change_credentials(&session), -1);
    test_restore_stdin();
}

static void test_change_credentials_invalid_new_password_rejected(void)
{
    Session session = register_and_login("acctuser3");

    CU_ASSERT_EQUAL(test_feed_stdin("GoodPass1\n1234\nshort\n"), 0);
    CU_ASSERT_EQUAL(account_change_credentials(&session), -1);
    test_restore_stdin();
}

static void test_change_credentials_not_logged_in_rejected(void)
{
    Session session;
    memset(&session, 0, sizeof(session));
    session.isLoggedIn = 0;

    CU_ASSERT_EQUAL(account_change_credentials(&session), -1);
    CU_ASSERT_EQUAL(account_change_credentials(NULL), -1);
}

static void test_deposit_funds_success(void)
{
    Session session = register_and_login("acctuser4");
    User found;
    double before = session.currentUser.balance;

    CU_ASSERT_EQUAL(test_feed_stdin("250.00\n"), 0);
    CU_ASSERT_EQUAL(account_deposit_funds(&session), 0);
    test_restore_stdin();

    CU_ASSERT_EQUAL(storage_find_user("acctuser4", &found), 1);
    CU_ASSERT_DOUBLE_EQUAL(found.balance, before + 250.00, 0.001);
    CU_ASSERT_DOUBLE_EQUAL(session.currentUser.balance, before + 250.00, 0.001);
}

static void test_deposit_funds_negative_amount_rejected(void)
{
    Session session = register_and_login("acctuser5");

    CU_ASSERT_EQUAL(test_feed_stdin("-10.00\n"), 0);
    CU_ASSERT_EQUAL(account_deposit_funds(&session), -1);
    test_restore_stdin();
}

static void test_deposit_funds_zero_amount_rejected(void)
{
    Session session = register_and_login("acctuser6");

    CU_ASSERT_EQUAL(test_feed_stdin("0\n"), 0);
    CU_ASSERT_EQUAL(account_deposit_funds(&session), -1);
    test_restore_stdin();
}

static void test_deposit_funds_not_logged_in_rejected(void)
{
    Session session;
    memset(&session, 0, sizeof(session));
    session.isLoggedIn = 0;

    CU_ASSERT_EQUAL(account_deposit_funds(&session), -1);
    CU_ASSERT_EQUAL(account_deposit_funds(NULL), -1);
}

CU_pSuite test_account_suite_create(void)
{
    CU_pSuite suite = CU_add_suite("account", account_suite_init, account_suite_cleanup);
    if (suite == NULL) { return NULL; }

    CU_add_test(suite, "change credentials: success", test_change_credentials_success);
    CU_add_test(suite, "change credentials: wrong current rejected", test_change_credentials_wrong_current_rejected);
    CU_add_test(suite, "change credentials: invalid new password rejected", test_change_credentials_invalid_new_password_rejected);
    CU_add_test(suite, "change credentials: not logged in rejected", test_change_credentials_not_logged_in_rejected);
    CU_add_test(suite, "deposit: success", test_deposit_funds_success);
    CU_add_test(suite, "deposit: negative amount rejected", test_deposit_funds_negative_amount_rejected);
    CU_add_test(suite, "deposit: zero amount rejected", test_deposit_funds_zero_amount_rejected);
    CU_add_test(suite, "deposit: not logged in rejected", test_deposit_funds_not_logged_in_rejected);

    return suite;
}
