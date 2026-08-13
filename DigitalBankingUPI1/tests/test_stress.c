/**
 * @file test_stress.c
 * @brief Stress and boundary-condition tests spanning storage,
 *        auth, and transaction modules together.
 */

#include <stdio.h>
#include <string.h>
#include <CUnit/CUnit.h>
#include "auth.h"
#include "storage.h"
#include "transaction.h"
#include "bank.h"
#include "test_common.h"
#include "test_runner.h"

#define STRESS_USER_COUNT 200

static int stress_suite_init(void)
{
    return test_sandbox_enter("stress");
}

static int stress_suite_cleanup(void)
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

/* --- Boundary conditions on username/password/PIN length --- */

static void test_boundary_username_max_length_accepted(void)
{
    /* MAX_USERNAME_LEN is 30; is_valid_username() in registration.c
     * accepts lengths in [3, MAX_USERNAME_LEN-1] = [3, 29]. */
    char username[MAX_USERNAME_LEN];
    char script[MAX_USERNAME_LEN + 32];
    User found;
    size_t i;

    for (i = 0U; i < (size_t)(MAX_USERNAME_LEN - 1); i++)
    {
        username[i] = (char)('a' + (int)(i % 26U));
    }
    username[MAX_USERNAME_LEN - 1] = '\0';
    CU_ASSERT_EQUAL(strlen(username), (size_t)(MAX_USERNAME_LEN - 1));

    (void)snprintf(script, sizeof(script), "%s\nGoodPass1\n1234\n", username);
    CU_ASSERT_EQUAL(test_feed_stdin(script), 0);
    CU_ASSERT_EQUAL(registration_register(), 0);
    test_restore_stdin();

    CU_ASSERT_EQUAL(storage_find_user(username, &found), 1);
}

static void test_boundary_overlong_username_line_truncated_safely(void)
{
    /* read_line()'s buffer is exactly MAX_USERNAME_LEN bytes, so
     * fgets() can never deliver more than MAX_USERNAME_LEN-1 (29)
     * characters on this path by construction -- there is no way to
     * reach is_valid_username()'s "too long" branch interactively.
     * What *is* reachable, and what real robustness requires, is
     * that feeding a much longer line does not overflow any buffer
     * and results in a safely truncated (and therefore still valid,
     * 29-character) username rather than corrupted or leaked data. */
    char overlongUsername[128];
    char script[160];
    User found;
    size_t i;

    for (i = 0U; i < (sizeof(overlongUsername) - 1U); i++)
    {
        overlongUsername[i] = (char)('c' + (int)(i % 23U));
    }
    overlongUsername[sizeof(overlongUsername) - 1U] = '\0';

    (void)snprintf(script, sizeof(script), "%s\nGoodPass1\n1234\n", overlongUsername);
    CU_ASSERT_EQUAL(test_feed_stdin(script), 0);
    CU_ASSERT_EQUAL(registration_register(), 0);
    test_restore_stdin();

    {
        char truncated[MAX_USERNAME_LEN];
        memcpy(truncated, overlongUsername, (size_t)(MAX_USERNAME_LEN - 1));
        truncated[MAX_USERNAME_LEN - 1] = '\0';
        CU_ASSERT_EQUAL(storage_find_user(truncated, &found), 1);
        CU_ASSERT_EQUAL(strlen(found.username), (size_t)(MAX_USERNAME_LEN - 1));
    }
}

static void test_boundary_username_too_short_rejected(void)
{
    CU_ASSERT_EQUAL(test_feed_stdin("ab\nGoodPass1\n1234\n"), 0);
    CU_ASSERT_EQUAL(registration_register(), -1);
    test_restore_stdin();
}

static void test_boundary_password_min_length_accepted(void)
{
    User found;
    CU_ASSERT_EQUAL(test_feed_stdin("boundpw1\n6chars\n1234\n"), 0);
    CU_ASSERT_EQUAL(registration_register(), 0);
    test_restore_stdin();
    CU_ASSERT_EQUAL(storage_find_user("boundpw1", &found), 1);
}

static void test_boundary_password_below_min_rejected(void)
{
    CU_ASSERT_EQUAL(test_feed_stdin("boundpw2\n5char\n1234\n"), 0);
    CU_ASSERT_EQUAL(registration_register(), -1);
    test_restore_stdin();
}

static void test_boundary_pin_4_and_6_digits_accepted(void)
{
    User found;

    CU_ASSERT_EQUAL(test_feed_stdin("boundpin1\nGoodPass1\n1234\n"), 0);
    CU_ASSERT_EQUAL(registration_register(), 0);
    test_restore_stdin();
    CU_ASSERT_EQUAL(storage_find_user("boundpin1", &found), 1);

    CU_ASSERT_EQUAL(test_feed_stdin("boundpin2\nGoodPass1\n123456\n"), 0);
    CU_ASSERT_EQUAL(registration_register(), 0);
    test_restore_stdin();
    CU_ASSERT_EQUAL(storage_find_user("boundpin2", &found), 1);
}

static void test_boundary_pin_5_digits_rejected(void)
{
    CU_ASSERT_EQUAL(test_feed_stdin("boundpin3\nGoodPass1\n12345\n"), 0);
    CU_ASSERT_EQUAL(registration_register(), -1);
    test_restore_stdin();
}

static void test_boundary_transfer_zero_and_negative_rejected(void)
{
    register_local_user("boundtx1", 100.0);
    CU_ASSERT_EQUAL(transaction_transfer("boundtx1", "target@digitalbank", 0.0), -1);
    CU_ASSERT_EQUAL(transaction_transfer("boundtx1", "target@digitalbank", -0.01), -1);
}

/* --- High-volume stress scenarios --- */

static void test_stress_many_users_registered_and_found(void)
{
    char username[32];
    int i;
    int foundCount = 0;

    for (i = 0; i < STRESS_USER_COUNT; i++)
    {
        (void)snprintf(username, sizeof(username), "stressuser%d", i);
        register_local_user(username, 100.0);
    }

    for (i = 0; i < STRESS_USER_COUNT; i++)
    {
        User found;
        (void)snprintf(username, sizeof(username), "stressuser%d", i);
        if (storage_find_user(username, &found) == 1)
        {
            foundCount++;
        }
    }

    CU_ASSERT_EQUAL(foundCount, STRESS_USER_COUNT);
}

static void test_stress_many_transactions_between_two_users(void)
{
    const int transferCount = 100;
    int i;
    User sender;
    User receiver;

    register_local_user("stresssender1", 100000.0);
    register_local_user("stressreceiver1", 0.0);

    for (i = 0; i < transferCount; i++)
    {
        CU_ASSERT_EQUAL(transaction_transfer("stresssender1", "stressreceiver1@digitalbank", 1.0), 0);
    }

    CU_ASSERT_EQUAL(storage_find_user("stresssender1", &sender), 1);
    CU_ASSERT_EQUAL(storage_find_user("stressreceiver1", &receiver), 1);
    CU_ASSERT_DOUBLE_EQUAL(sender.balance, 100000.0 - (double)transferCount, 0.001);
    CU_ASSERT_DOUBLE_EQUAL(receiver.balance, (double)transferCount, 0.001);

    CU_ASSERT_EQUAL(transaction_show_history("stresssender1"), transferCount);
}

static void test_stress_repeated_balance_updates(void)
{
    const int updateCount = 300;
    int i;
    User found;

    register_local_user("stressbal1", 0.0);

    for (i = 0; i < updateCount; i++)
    {
        CU_ASSERT_EQUAL(storage_update_balance("stressbal1", (double)i), 0);
    }

    CU_ASSERT_EQUAL(storage_find_user("stressbal1", &found), 1);
    CU_ASSERT_DOUBLE_EQUAL(found.balance, (double)(updateCount - 1), 0.001);
}

CU_pSuite test_stress_suite_create(void)
{
    CU_pSuite suite = CU_add_suite("stress", stress_suite_init, stress_suite_cleanup);
    if (suite == NULL) { return NULL; }

    CU_add_test(suite, "boundary: max-length username accepted", test_boundary_username_max_length_accepted);
    CU_add_test(suite, "boundary: overlong username line truncated safely", test_boundary_overlong_username_line_truncated_safely);
    CU_add_test(suite, "boundary: too-short username rejected", test_boundary_username_too_short_rejected);
    CU_add_test(suite, "boundary: min-length password accepted", test_boundary_password_min_length_accepted);
    CU_add_test(suite, "boundary: below-min password rejected", test_boundary_password_below_min_rejected);
    CU_add_test(suite, "boundary: 4/6-digit PIN accepted", test_boundary_pin_4_and_6_digits_accepted);
    CU_add_test(suite, "boundary: 5-digit PIN rejected", test_boundary_pin_5_digits_rejected);
    CU_add_test(suite, "boundary: zero/negative transfer rejected", test_boundary_transfer_zero_and_negative_rejected);
    CU_add_test(suite, "stress: many users registered", test_stress_many_users_registered_and_found);
    CU_add_test(suite, "stress: many transactions", test_stress_many_transactions_between_two_users);
    CU_add_test(suite, "stress: repeated balance updates", test_stress_repeated_balance_updates);

    return suite;
}
