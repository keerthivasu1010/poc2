/**
 * @file test_auth.c
 * @brief Unit tests for the auth module (src/registration.c,
 *        src/login.c) covering registration and login flows.
 *
 * registration_register() and login_authenticate() are interactive:
 * they read prompts from stdin. To unit test them without changing
 * their public interface, these tests redirect stdin to an in-memory
 * buffer (see test_common.h) that supplies the same lines a user
 * would type at the menu.
 */

#include <string.h>
#include <CUnit/CUnit.h>
#include "auth.h"
#include "storage.h"
#include "test_common.h"
#include "test_runner.h"

static int auth_suite_init(void)
{
    return test_sandbox_enter("auth");
}

static int auth_suite_cleanup(void)
{
    test_sandbox_leave();
    return 0;
}

/* --- registration_register --- */

static void test_register_success(void)
{
    User found;

    CU_ASSERT_EQUAL(test_feed_stdin("authuser1\nGoodPass1\n1234\n"), 0);
    CU_ASSERT_EQUAL(registration_register(), 0);
    test_restore_stdin();

    CU_ASSERT_EQUAL(storage_find_user("authuser1", &found), 1);
    CU_ASSERT_STRING_EQUAL(found.upiID, "authuser1@digitalbank");
    CU_ASSERT_DOUBLE_EQUAL(found.balance, 1000.00, 0.001);
}

static void test_register_invalid_username_rejected(void)
{
    CU_ASSERT_EQUAL(test_feed_stdin("ab\n"), 0);
    CU_ASSERT_EQUAL(registration_register(), -1);
    test_restore_stdin();
}

static void test_register_invalid_password_rejected(void)
{
    CU_ASSERT_EQUAL(test_feed_stdin("authuser2\nshort\n"), 0);
    CU_ASSERT_EQUAL(registration_register(), -1);
    test_restore_stdin();
}

static void test_register_invalid_pin_rejected(void)
{
    CU_ASSERT_EQUAL(test_feed_stdin("authuser3\nGoodPass1\n12\n"), 0);
    CU_ASSERT_EQUAL(registration_register(), -1);
    test_restore_stdin();
}

static void test_register_duplicate_username_rejected(void)
{
    User found;

    CU_ASSERT_EQUAL(test_feed_stdin("authuser4\nGoodPass1\n1234\n"), 0);
    CU_ASSERT_EQUAL(registration_register(), 0);
    test_restore_stdin();

    CU_ASSERT_EQUAL(test_feed_stdin("authuser4\nOtherPass1\n5678\n"), 0);
    CU_ASSERT_EQUAL(registration_register(), -1);
    test_restore_stdin();

    /* Original account must be untouched. */
    CU_ASSERT_EQUAL(storage_find_user("authuser4", &found), 1);
}

static void test_register_eof_on_username(void)
{
    CU_ASSERT_EQUAL(test_feed_stdin(""), 0);
    CU_ASSERT_EQUAL(registration_register(), -1);
    test_restore_stdin();
}

/* --- login_authenticate --- */

static void test_login_success(void)
{
    Session session;
    memset(&session, 0, sizeof(session));

    CU_ASSERT_EQUAL(test_feed_stdin("authuser5\nGoodPass1\n1234\n"), 0);
    CU_ASSERT_EQUAL(registration_register(), 0);
    test_restore_stdin();

    CU_ASSERT_EQUAL(test_feed_stdin("authuser5\nGoodPass1\n1234\n"), 0);
    CU_ASSERT_EQUAL(login_authenticate(&session), 0);
    test_restore_stdin();

    CU_ASSERT_EQUAL(session.isLoggedIn, 1);
    CU_ASSERT_STRING_EQUAL(session.currentUser.username, "authuser5");
}

static void test_login_wrong_password_rejected(void)
{
    Session session;
    memset(&session, 0, sizeof(session));

    CU_ASSERT_EQUAL(test_feed_stdin("authuser6\nGoodPass1\n1234\n"), 0);
    CU_ASSERT_EQUAL(registration_register(), 0);
    test_restore_stdin();

    CU_ASSERT_EQUAL(test_feed_stdin("authuser6\nWrongPass1\n1234\n"), 0);
    CU_ASSERT_EQUAL(login_authenticate(&session), -1);
    test_restore_stdin();

    CU_ASSERT_EQUAL(session.isLoggedIn, 0);
}

static void test_login_unknown_user_rejected(void)
{
    Session session;
    memset(&session, 0, sizeof(session));

    CU_ASSERT_EQUAL(test_feed_stdin("nosuchuser_xyz\nWhatever1\n1234\n"), 0);
    CU_ASSERT_EQUAL(login_authenticate(&session), -1);
    test_restore_stdin();
}

static void test_login_null_session_rejected(void)
{
    CU_ASSERT_EQUAL(login_authenticate(NULL), -1);
}

static void test_login_lockout_after_max_failed_attempts(void)
{
    Session session;
    int i;

    memset(&session, 0, sizeof(session));

    CU_ASSERT_EQUAL(test_feed_stdin("authuser7\nGoodPass1\n1234\n"), 0);
    CU_ASSERT_EQUAL(registration_register(), 0);
    test_restore_stdin();

    /* MAX_FAILED_LOGIN_ATTEMPTS consecutive bad logins should lock
     * the account; a subsequent attempt with the CORRECT password
     * must then also be rejected because the account is locked. */
    for (i = 0; i < 5; i++)
    {
        CU_ASSERT_EQUAL(test_feed_stdin("authuser7\nWrongPass1\n1234\n"), 0);
        CU_ASSERT_EQUAL(login_authenticate(&session), -1);
        test_restore_stdin();
    }

    CU_ASSERT_EQUAL(test_feed_stdin("authuser7\nGoodPass1\n1234\n"), 0);
    CU_ASSERT_EQUAL(login_authenticate(&session), -1);
    test_restore_stdin();
    CU_ASSERT_EQUAL(session.isLoggedIn, 0);
}

CU_pSuite test_auth_suite_create(void)
{
    CU_pSuite suite = CU_add_suite("auth", auth_suite_init, auth_suite_cleanup);
    if (suite == NULL) { return NULL; }

    CU_add_test(suite, "register: success", test_register_success);
    CU_add_test(suite, "register: invalid username rejected", test_register_invalid_username_rejected);
    CU_add_test(suite, "register: invalid password rejected", test_register_invalid_password_rejected);
    CU_add_test(suite, "register: invalid PIN rejected", test_register_invalid_pin_rejected);
    CU_add_test(suite, "register: duplicate username rejected", test_register_duplicate_username_rejected);
    CU_add_test(suite, "register: EOF on username", test_register_eof_on_username);
    CU_add_test(suite, "login: success", test_login_success);
    CU_add_test(suite, "login: wrong password rejected", test_login_wrong_password_rejected);
    CU_add_test(suite, "login: unknown user rejected", test_login_unknown_user_rejected);
    CU_add_test(suite, "login: NULL session rejected", test_login_null_session_rejected);
    CU_add_test(suite, "login: lockout after max failed attempts", test_login_lockout_after_max_failed_attempts);

    return suite;
}
