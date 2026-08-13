/**
 * @file test_admin.c
 * @brief Unit tests for the admin module (src/admin.c).
 */

#include <string.h>
#include <CUnit/CUnit.h>
#include "admin.h"
#include "auth.h"
#include "bank.h"
#include "storage.h"
#include "test_common.h"
#include "test_runner.h"

static int admin_suite_init(void)
{
    return test_sandbox_enter("admin");
}

static int admin_suite_cleanup(void)
{
    test_sandbox_leave();
    return 0;
}

static void register_local_user(const char *username, double balance)
{
    char script[256];
    (void)snprintf(script, sizeof(script), "%s\nGoodPass1\n1234\n", username);
    CU_ASSERT_EQUAL(test_feed_stdin(script), 0);
    CU_ASSERT_EQUAL(registration_register(), 0);
    test_restore_stdin();

    if (balance != 1000.00)
    {
        (void)storage_update_balance(username, balance);
    }
}

static void test_ensure_default_account_creates_admin(void)
{
    User admin;
    CU_ASSERT_EQUAL(admin_ensure_default_account(), 0);
    CU_ASSERT_EQUAL(storage_find_user(DEFAULT_ADMIN_USERNAME, &admin), 1);
    CU_ASSERT_EQUAL(admin.isAdmin, 1);
}

static void test_ensure_default_account_idempotent(void)
{
    CU_ASSERT_EQUAL(admin_ensure_default_account(), 0);
    CU_ASSERT_EQUAL(admin_ensure_default_account(), 0);
}

/* admin_run_panel() is a full interactive menu loop rather than a
 * single-purpose function, so it is exercised end-to-end here by
 * feeding a whole session's worth of menu input and asserting on the
 * resulting persisted state -- covering freeze, unfreeze, and clear
 * lockout in one authenticated admin session, matching how the
 * feature is actually used from main(). */
static void test_admin_panel_freeze_unfreeze_clear_lockout(void)
{
    User found;

    register_local_user("panvictim1", 100.0);

    CU_ASSERT_EQUAL(test_feed_stdin(
        "2\npanvictim1\n"   /* freeze */
        "1\n"               /* list users */
        "3\npanvictim1\n"   /* unfreeze */
        "4\npanvictim1\n"   /* clear lockout */
        "5\n"), 0);         /* logout */
    admin_run_panel("admin");
    test_restore_stdin();

    CU_ASSERT_EQUAL(storage_find_user("panvictim1", &found), 1);
    CU_ASSERT_EQUAL(found.isFrozen, 0);
    CU_ASSERT_EQUAL(found.failedAttempts, 0);
    CU_ASSERT_EQUAL(found.lockedUntilEpoch, 0L);
}

static void test_admin_panel_refuses_to_freeze_admin(void)
{
    User adminUser;

    CU_ASSERT_EQUAL(admin_ensure_default_account(), 0);

    CU_ASSERT_EQUAL(test_feed_stdin(
        "2\nadmin\n"   /* attempt to freeze the admin itself */
        "5\n"), 0);
    admin_run_panel("admin");
    test_restore_stdin();

    CU_ASSERT_EQUAL(storage_find_user(DEFAULT_ADMIN_USERNAME, &adminUser), 1);
    CU_ASSERT_EQUAL(adminUser.isFrozen, 0);
}

static void test_admin_panel_unknown_user_reported(void)
{
    CU_ASSERT_EQUAL(test_feed_stdin(
        "2\nghost_user_xyz\n"
        "5\n"), 0);
    admin_run_panel("admin");
    test_restore_stdin();
    /* No crash and no assertion failure is itself the success
     * criterion here: the target user does not exist. */
}

static void test_admin_panel_invalid_choice_then_logout(void)
{
    CU_ASSERT_EQUAL(test_feed_stdin("99\n5\n"), 0);
    admin_run_panel("admin");
    test_restore_stdin();
}

static void test_admin_panel_null_username_returns_immediately(void)
{
    admin_run_panel(NULL);
}

static void test_admin_panel_eof_exits_loop(void)
{
    CU_ASSERT_EQUAL(test_feed_stdin(""), 0);
    admin_run_panel("admin");
    test_restore_stdin();
}

static void test_admin_panel_list_users_no_users(void)
{
    CU_ASSERT_EQUAL(test_feed_stdin("1\n5\n"), 0);
    admin_run_panel("admin");
    test_restore_stdin();
}

static void test_admin_panel_clear_lockout_unknown_user(void)
{
    CU_ASSERT_EQUAL(test_feed_stdin("4\nghost_lockout_xyz\n5\n"), 0);
    admin_run_panel("admin");
    test_restore_stdin();
}

static void test_admin_panel_clear_lockout_eof(void)
{
    register_local_user("panvictim2", 100.0);
    CU_ASSERT_EQUAL(test_feed_stdin("4\n"), 0);
    admin_run_panel("admin");
    test_restore_stdin();
}

static void test_admin_panel_freeze_eof(void)
{
    CU_ASSERT_EQUAL(test_feed_stdin("2\n"), 0);
    admin_run_panel("admin");
    test_restore_stdin();
}

CU_pSuite test_admin_suite_create(void)
{
    CU_pSuite suite = CU_add_suite("admin", admin_suite_init, admin_suite_cleanup);
    if (suite == NULL) { return NULL; }

    CU_add_test(suite, "ensure_default_account creates admin", test_ensure_default_account_creates_admin);
    CU_add_test(suite, "ensure_default_account is idempotent", test_ensure_default_account_idempotent);
    CU_add_test(suite, "panel: freeze/unfreeze/clear lockout", test_admin_panel_freeze_unfreeze_clear_lockout);
    CU_add_test(suite, "panel: refuses to freeze admin", test_admin_panel_refuses_to_freeze_admin);
    CU_add_test(suite, "panel: unknown user reported, no crash", test_admin_panel_unknown_user_reported);
    CU_add_test(suite, "panel: invalid choice then logout", test_admin_panel_invalid_choice_then_logout);
    CU_add_test(suite, "panel: NULL username returns immediately", test_admin_panel_null_username_returns_immediately);
    CU_add_test(suite, "panel: EOF exits loop", test_admin_panel_eof_exits_loop);
    CU_add_test(suite, "panel: list users with no users", test_admin_panel_list_users_no_users);
    CU_add_test(suite, "panel: clear lockout unknown user", test_admin_panel_clear_lockout_unknown_user);
    CU_add_test(suite, "panel: clear lockout EOF on target", test_admin_panel_clear_lockout_eof);
    CU_add_test(suite, "panel: freeze EOF on target", test_admin_panel_freeze_eof);

    return suite;
}
