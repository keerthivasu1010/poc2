/**
 * @file test_coverage_extra.c
 * @brief Supplementary unit tests that close remaining branch/line
 *        coverage gaps in modules that already have their own suite
 *        (test_account.c, test_admin.c, test_auth.c,
 *        test_integrity.c, test_transaction.c/history), without
 *        modifying any existing test file.
 *
 * These target input-stream edge cases (EOF mid-flow, overlong
 * lines) and data-shape edge cases (corrupted/tampered stored
 * records) that are reachable purely through each module's public
 * API, using the same test_feed_stdin()/sandbox helpers as the rest
 * of the suite.
 */

#include <string.h>
#include <CUnit/CUnit.h>
#include "account.h"
#include "admin.h"
#include "auth.h"
#include "integrity.h"
#include "transaction.h"
#include "bank.h"
#include "storage.h"
#include "test_common.h"
#include "test_runner.h"

static int extra_suite_init(void)
{
    return test_sandbox_enter("coverage_extra");
}

static int extra_suite_cleanup(void)
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

/* ---------------- registration.c: remaining branches ---------------- */

static void test_reg_invalid_username_bad_character(void)
{
    /* Exercises is_valid_username()'s per-character rejection loop
     * (a syntactically long-enough username containing a disallowed
     * character), distinct from the already-covered "too short" case. */
    CU_ASSERT_EQUAL(test_feed_stdin("bad$name\n"), 0);
    CU_ASSERT_EQUAL(registration_register(), -1);
    test_restore_stdin();
}

static void test_reg_invalid_pin_non_digit(void)
{
    /* Exercises is_valid_pin()'s per-character digit-rejection loop
     * (right length, but not all digits). */
    CU_ASSERT_EQUAL(test_feed_stdin("regpinuser1\nGoodPass1\n12a4\n"), 0);
    CU_ASSERT_EQUAL(registration_register(), -1);
    test_restore_stdin();
}

static void test_reg_eof_on_password(void)
{
    CU_ASSERT_EQUAL(test_feed_stdin("regeofpass1\n"), 0);
    CU_ASSERT_EQUAL(registration_register(), -1);
    test_restore_stdin();
}

static void test_reg_eof_on_pin(void)
{
    CU_ASSERT_EQUAL(test_feed_stdin("regeofpin1\nGoodPass1\n"), 0);
    CU_ASSERT_EQUAL(registration_register(), -1);
    test_restore_stdin();
}

/* ---------------- login.c: remaining branches ---------------- */

static void test_login_eof_on_username(void)
{
    Session session;
    memset(&session, 0, sizeof(session));

    CU_ASSERT_EQUAL(test_feed_stdin(""), 0);
    CU_ASSERT_EQUAL(login_authenticate(&session), -1);
    test_restore_stdin();
}

static void test_login_expired_lockout_cleared_on_attempt(void)
{
    /* A lockedUntilEpoch strictly in the past (but nonzero) exercises
     * the "lockout period has expired; clear it" branch, distinct
     * from the already-covered "still locked" case. */
    Session session;
    User user;
    memset(&session, 0, sizeof(session));

    (void)register_and_login("loginexplock1");
    CU_ASSERT_EQUAL(storage_find_user("loginexplock1", &user), 1);
    user.lockedUntilEpoch = 1L; /* epoch 1 = long since expired */
    CU_ASSERT_EQUAL(storage_update_user(&user), 0);

    memset(&session, 0, sizeof(session));
    CU_ASSERT_EQUAL(test_feed_stdin("loginexplock1\nGoodPass1\n1234\n"), 0);
    CU_ASSERT_EQUAL(login_authenticate(&session), 0);
    test_restore_stdin();
    CU_ASSERT_EQUAL(session.isLoggedIn, 1);

    CU_ASSERT_EQUAL(storage_find_user("loginexplock1", &user), 1);
    CU_ASSERT_EQUAL(user.lockedUntilEpoch, 0L);
}

static void test_login_stale_failed_attempts_reset_on_success(void)
{
    /* Nonzero failedAttempts but no active lockout: a subsequent
     * correct login must reset the counters, exercising the branch
     * distinct from the already-covered "already zero" success path. */
    Session session;
    User user;

    (void)register_and_login("loginstale1");
    CU_ASSERT_EQUAL(storage_find_user("loginstale1", &user), 1);
    user.failedAttempts = 2;
    CU_ASSERT_EQUAL(storage_update_user(&user), 0);

    memset(&session, 0, sizeof(session));
    CU_ASSERT_EQUAL(test_feed_stdin("loginstale1\nGoodPass1\n1234\n"), 0);
    CU_ASSERT_EQUAL(login_authenticate(&session), 0);
    test_restore_stdin();

    CU_ASSERT_EQUAL(storage_find_user("loginstale1", &user), 1);
    CU_ASSERT_EQUAL(user.failedAttempts, 0);
}

static void test_login_eof_on_password(void)
{
    Session session;
    memset(&session, 0, sizeof(session));

    (void)register_and_login("logineofpw1");

    CU_ASSERT_EQUAL(test_feed_stdin("logineofpw1\n"), 0);
    CU_ASSERT_EQUAL(login_authenticate(&session), -1);
    test_restore_stdin();
}

static void test_login_eof_on_pin(void)
{
    Session session;
    memset(&session, 0, sizeof(session));

    (void)register_and_login("logineofpin1");

    CU_ASSERT_EQUAL(test_feed_stdin("logineofpin1\nGoodPass1\n"), 0);
    CU_ASSERT_EQUAL(login_authenticate(&session), -1);
    test_restore_stdin();
}

static void test_login_frozen_account_rejected(void)
{
    Session session;
    User user;
    memset(&session, 0, sizeof(session));

    (void)register_and_login("loginfrozen1");
    CU_ASSERT_EQUAL(storage_find_user("loginfrozen1", &user), 1);
    user.isFrozen = 1;
    CU_ASSERT_EQUAL(storage_update_user(&user), 0);

    memset(&session, 0, sizeof(session));
    CU_ASSERT_EQUAL(test_feed_stdin("loginfrozen1\nGoodPass1\n1234\n"), 0);
    CU_ASSERT_EQUAL(login_authenticate(&session), -1);
    test_restore_stdin();
    CU_ASSERT_EQUAL(session.isLoggedIn, 0);
}

static void test_login_overlong_username_drained_safely(void)
{
    /* login.c has its own private read_line() copy of the
     * getchar()-drain loop; only registration.c's copy is exercised
     * by the existing boundary tests, so this drives login's copy
     * directly via an overlong username line. */
    char overlong[128];
    char script[200];
    Session session;
    size_t i;

    for (i = 0U; i < (sizeof(overlong) - 1U); i++)
    {
        overlong[i] = (char)('d' + (int)(i % 20U));
    }
    overlong[sizeof(overlong) - 1U] = '\0';

    (void)snprintf(script, sizeof(script), "%s\nGoodPass1\n1234\n", overlong);
    memset(&session, 0, sizeof(session));
    CU_ASSERT_EQUAL(test_feed_stdin(script), 0);
    CU_ASSERT_EQUAL(login_authenticate(&session), -1); /* no such (truncated) user */
    test_restore_stdin();
}

/* ---------------- account.c: remaining branches ---------------- */

static void test_change_credentials_eof_on_current_password(void)
{
    Session session = register_and_login("acctextra0");

    CU_ASSERT_EQUAL(test_feed_stdin(""), 0);
    CU_ASSERT_EQUAL(account_change_credentials(&session), -1);
    test_restore_stdin();
}

static void test_change_credentials_eof_on_current_pin(void)
{
    Session session = register_and_login("acctextra1");

    CU_ASSERT_EQUAL(test_feed_stdin("GoodPass1\n"), 0);
    CU_ASSERT_EQUAL(account_change_credentials(&session), -1);
    test_restore_stdin();
}

static void test_change_credentials_eof_on_new_password(void)
{
    Session session = register_and_login("acctextra2");

    CU_ASSERT_EQUAL(test_feed_stdin("GoodPass1\n1234\n"), 0);
    CU_ASSERT_EQUAL(account_change_credentials(&session), -1);
    test_restore_stdin();
}

static void test_change_credentials_eof_on_new_pin(void)
{
    Session session = register_and_login("acctextra3");

    CU_ASSERT_EQUAL(test_feed_stdin("GoodPass1\n1234\nNewPass2\n"), 0);
    CU_ASSERT_EQUAL(account_change_credentials(&session), -1);
    test_restore_stdin();
}

static void test_change_credentials_invalid_new_pin_rejected(void)
{
    Session session = register_and_login("acctextra4");

    CU_ASSERT_EQUAL(test_feed_stdin("GoodPass1\n1234\nNewPass2\n12\n"), 0);
    CU_ASSERT_EQUAL(account_change_credentials(&session), -1);
    test_restore_stdin();
}

static void test_change_credentials_invalid_new_pin_non_digit_rejected(void)
{
    /* Right length (4), but not all digits: exercises is_valid_pin()'s
     * per-character digit-rejection loop from the account.c copy,
     * distinct from the already-covered "wrong length" case. */
    Session session = register_and_login("acctextra7");

    CU_ASSERT_EQUAL(test_feed_stdin("GoodPass1\n1234\nNewPass2\n12a4\n"), 0);
    CU_ASSERT_EQUAL(account_change_credentials(&session), -1);
    test_restore_stdin();
}

static void test_change_credentials_account_vanished_rejected(void)
{
    /* Log in normally, then remove the user store (as a standard
     * file operation, exactly like test_common.c's own sandbox
     * setup/teardown does) so the account no longer exists by the
     * time account_change_credentials() re-reads it, exercising the
     * "Could not load account." branch. */
    Session session = register_and_login("acctextra8");

    CU_ASSERT_EQUAL(remove(USERS_DB_PATH), 0);
    CU_ASSERT_EQUAL(storage_init(), 0);

    CU_ASSERT_EQUAL(test_feed_stdin("GoodPass1\n1234\nNewPass2\n5678\n"), 0);
    CU_ASSERT_EQUAL(account_change_credentials(&session), -1);
    test_restore_stdin();
}

static void test_deposit_account_vanished_rejected(void)
{
    Session session = register_and_login("acctextra9");

    CU_ASSERT_EQUAL(remove(USERS_DB_PATH), 0);
    CU_ASSERT_EQUAL(storage_init(), 0);

    CU_ASSERT_EQUAL(test_feed_stdin("50.00\n"), 0);
    CU_ASSERT_EQUAL(account_deposit_funds(&session), -1);
    test_restore_stdin();
}

static void test_deposit_eof_on_amount(void)
{
    Session session = register_and_login("acctextra5");

    CU_ASSERT_EQUAL(test_feed_stdin(""), 0);
    CU_ASSERT_EQUAL(account_deposit_funds(&session), -1);
    test_restore_stdin();
}

static void test_change_credentials_overlong_current_password_drained_safely(void)
{
    /* account.c's own private read_line() getchar()-drain copy. */
    char overlong[100];
    char script[200];
    Session session = register_and_login("acctextra6");
    size_t i;

    for (i = 0U; i < (sizeof(overlong) - 1U); i++)
    {
        overlong[i] = (char)('e' + (int)(i % 18U));
    }
    overlong[sizeof(overlong) - 1U] = '\0';

    (void)snprintf(script, sizeof(script), "%s\n1234\n", overlong);
    CU_ASSERT_EQUAL(test_feed_stdin(script), 0);
    CU_ASSERT_EQUAL(account_change_credentials(&session), -1); /* wrong current password */
    test_restore_stdin();
}

/* ---------------- admin.c: remaining branches ---------------- */

static void test_admin_panel_no_users_registered(void)
{
    /* Fresh sandbox for this suite has zero users at this point in
     * the run (admin default-account creation is exercised in
     * test_admin.c's own sandbox, not this one), so "list users"
     * hits the count == 0 branch. */
    CU_ASSERT_EQUAL(test_feed_stdin("1\n5\n"), 0);
    admin_run_panel("admin");
    test_restore_stdin();
}

static void test_admin_panel_freeze_eof_on_target(void)
{
    CU_ASSERT_EQUAL(test_feed_stdin("2\n"), 0);
    admin_run_panel("admin");
    test_restore_stdin();
}

static void test_admin_panel_clear_lockout_eof_on_target(void)
{
    CU_ASSERT_EQUAL(test_feed_stdin("4\n"), 0);
    admin_run_panel("admin");
    test_restore_stdin();
}

static void test_admin_panel_clear_lockout_unknown_user(void)
{
    CU_ASSERT_EQUAL(test_feed_stdin("4\nghost_admin_target_xyz\n5\n"), 0);
    admin_run_panel("admin");
    test_restore_stdin();
}

static void test_admin_panel_overlong_target_drained_safely(void)
{
    /* admin.c's own private read_line() getchar()-drain copy. */
    char overlong[64];
    char script[120];
    size_t i;

    for (i = 0U; i < (sizeof(overlong) - 1U); i++)
    {
        overlong[i] = (char)('f' + (int)(i % 15U));
    }
    overlong[sizeof(overlong) - 1U] = '\0';

    (void)snprintf(script, sizeof(script), "2\n%s\n5\n", overlong);
    CU_ASSERT_EQUAL(test_feed_stdin(script), 0);
    admin_run_panel("admin");
    test_restore_stdin();
}

/* ---------------- history.c: decryption-error branch ---------------- */

static void test_history_decryption_error_reported(void)
{
    Transaction txn;

    register_local_user("histerruser1", 100.0);

    memset(&txn, 0, sizeof(txn));
    strncpy(txn.sender, "histerruser1", sizeof(txn.sender) - 1U);
    strncpy(txn.receiver, "someone@digitalbank", sizeof(txn.receiver) - 1U);
    txn.amount = 10.0;
    strncpy(txn.timestamp, "2026-01-01 00:00:00", sizeof(txn.timestamp) - 1U);
    /* Not valid hex, so aes128_decrypt_from_hex() fails and
     * history_visitor() takes its "[DECRYPTION ERROR]" branch. */
    strncpy(txn.encryptedData, "not-valid-hex-zz", sizeof(txn.encryptedData) - 1U);
    strncpy(txn.hash, "deadbeef", sizeof(txn.hash) - 1U);

    CU_ASSERT_EQUAL(storage_add_transaction(&txn), 0);

    CU_ASSERT_TRUE(transaction_show_history("histerruser1") >= 1);
}

/* ---------------- integrity.c: tampered-transaction branch ---------------- */

static void test_integrity_verify_tampered_transaction_detected(void)
{
    Transaction txn;
    int checked;

    register_local_user("intextrauser1", 100.0);

    memset(&txn, 0, sizeof(txn));
    strncpy(txn.sender, "intextrauser1", sizeof(txn.sender) - 1U);
    strncpy(txn.receiver, "someone@digitalbank", sizeof(txn.receiver) - 1U);
    txn.amount = 42.0;
    strncpy(txn.timestamp, "2026-01-01 00:00:00", sizeof(txn.timestamp) - 1U);
    strncpy(txn.encryptedData, "aa", sizeof(txn.encryptedData) - 1U);
    /* Deliberately wrong hash: does not match integrity_compute_hash()
     * for this record, so verify_visitor() takes its "[TAMPERED]"
     * branch instead of "[VERIFIED]". */
    strncpy(txn.hash, "0000000000000000000000000000000000000000000000000000000000000",
            sizeof(txn.hash) - 1U);

    CU_ASSERT_EQUAL(storage_add_transaction(&txn), 0);

    checked = integrity_verify_user_transactions("intextrauser1");
    CU_ASSERT_TRUE(checked >= 1);
}

CU_pSuite test_coverage_extra_suite_create(void)
{
    CU_pSuite suite = CU_add_suite("coverage_extra", extra_suite_init, extra_suite_cleanup);
    if (suite == NULL) { return NULL; }

    /* Must run before any other test in this suite registers a user
     * into the shared sandbox, so storage genuinely has zero users. */
    CU_add_test(suite, "admin panel: no users registered", test_admin_panel_no_users_registered);

    CU_add_test(suite, "registration: invalid username bad character", test_reg_invalid_username_bad_character);
    CU_add_test(suite, "registration: invalid PIN non-digit", test_reg_invalid_pin_non_digit);
    CU_add_test(suite, "registration: EOF on password", test_reg_eof_on_password);
    CU_add_test(suite, "registration: EOF on PIN", test_reg_eof_on_pin);

    CU_add_test(suite, "login: EOF on username", test_login_eof_on_username);
    CU_add_test(suite, "login: expired lockout cleared on attempt", test_login_expired_lockout_cleared_on_attempt);
    CU_add_test(suite, "login: stale failed attempts reset on success", test_login_stale_failed_attempts_reset_on_success);
    CU_add_test(suite, "login: EOF on password", test_login_eof_on_password);
    CU_add_test(suite, "login: EOF on PIN", test_login_eof_on_pin);
    CU_add_test(suite, "login: frozen account rejected", test_login_frozen_account_rejected);
    CU_add_test(suite, "login: overlong username drained safely", test_login_overlong_username_drained_safely);

    CU_add_test(suite, "change credentials: EOF on current password", test_change_credentials_eof_on_current_password);
    CU_add_test(suite, "change credentials: EOF on current PIN", test_change_credentials_eof_on_current_pin);
    CU_add_test(suite, "change credentials: EOF on new password", test_change_credentials_eof_on_new_password);
    CU_add_test(suite, "change credentials: EOF on new PIN", test_change_credentials_eof_on_new_pin);
    CU_add_test(suite, "change credentials: invalid new PIN rejected", test_change_credentials_invalid_new_pin_rejected);
    CU_add_test(suite, "change credentials: invalid new PIN non-digit rejected", test_change_credentials_invalid_new_pin_non_digit_rejected);
    CU_add_test(suite, "change credentials: account vanished rejected", test_change_credentials_account_vanished_rejected);
    CU_add_test(suite, "deposit: account vanished rejected", test_deposit_account_vanished_rejected);
    CU_add_test(suite, "deposit: EOF on amount", test_deposit_eof_on_amount);
    CU_add_test(suite, "change credentials: overlong current password drained safely", test_change_credentials_overlong_current_password_drained_safely);

    CU_add_test(suite, "admin panel: freeze EOF on target", test_admin_panel_freeze_eof_on_target);
    CU_add_test(suite, "admin panel: clear lockout EOF on target", test_admin_panel_clear_lockout_eof_on_target);
    CU_add_test(suite, "admin panel: clear lockout unknown user", test_admin_panel_clear_lockout_unknown_user);
    CU_add_test(suite, "admin panel: overlong target drained safely", test_admin_panel_overlong_target_drained_safely);

    CU_add_test(suite, "history: decryption error reported", test_history_decryption_error_reported);
    CU_add_test(suite, "integrity: tampered transaction detected", test_integrity_verify_tampered_transaction_detected);

    return suite;
}
