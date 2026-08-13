/**
 * @file test_audit.c
 * @brief Unit tests for the audit module (src/audit.c).
 */

#include <stdio.h>
#include <string.h>
#include <CUnit/CUnit.h>
#include "audit.h"
#include "bank.h"
#include "test_common.h"
#include "test_runner.h"

static int audit_suite_init(void)
{
    return test_sandbox_enter("audit");
}

static int audit_suite_cleanup(void)
{
    test_sandbox_leave();
    return 0;
}

static long count_lines_containing(const char *needle)
{
    FILE *fp = fopen(AUDIT_LOG_PATH, "r");
    char line[MAX_LINE_LEN];
    long count = 0L;

    if (fp == NULL)
    {
        return -1L;
    }

    while (fgets(line, sizeof(line), fp) != NULL)
    {
        if (strstr(line, needle) != NULL)
        {
            count++;
        }
    }

    (void)fclose(fp);
    return count;
}

static void test_audit_log_appends_line(void)
{
    long before = count_lines_containing("unit-test-marker-alpha");
    CU_ASSERT_EQUAL(audit_log("testuser", "unit-test-marker-alpha"), 0);
    CU_ASSERT_EQUAL(count_lines_containing("unit-test-marker-alpha"), before + 1L);
}

static void test_audit_log_multiple_appends(void)
{
    long before = count_lines_containing("unit-test-marker-beta");
    CU_ASSERT_EQUAL(audit_log("testuser", "unit-test-marker-beta"), 0);
    CU_ASSERT_EQUAL(audit_log("testuser", "unit-test-marker-beta"), 0);
    CU_ASSERT_EQUAL(audit_log("testuser", "unit-test-marker-beta"), 0);
    CU_ASSERT_EQUAL(count_lines_containing("unit-test-marker-beta"), before + 3L);
}

static void test_audit_log_null_username_defaults_to_system(void)
{
    CU_ASSERT_EQUAL(audit_log(NULL, "unit-test-marker-gamma"), 0);
    CU_ASSERT_TRUE(count_lines_containing("user=SYSTEM event=unit-test-marker-gamma") >= 1L);
}

static void test_audit_log_null_event_handled(void)
{
    CU_ASSERT_EQUAL(audit_log("testuser", NULL), 0);
}

static void test_audit_log_contains_timestamp_brackets(void)
{
    CU_ASSERT_EQUAL(audit_log("testuser", "unit-test-marker-delta"), 0);
    CU_ASSERT_TRUE(count_lines_containing("[20") >= 1L);
}

CU_pSuite test_audit_suite_create(void)
{
    CU_pSuite suite = CU_add_suite("audit", audit_suite_init, audit_suite_cleanup);
    if (suite == NULL) { return NULL; }

    CU_add_test(suite, "log appends a line", test_audit_log_appends_line);
    CU_add_test(suite, "multiple appends accumulate", test_audit_log_multiple_appends);
    CU_add_test(suite, "NULL username defaults to SYSTEM", test_audit_log_null_username_defaults_to_system);
    CU_add_test(suite, "NULL event handled without crash", test_audit_log_null_event_handled);
    CU_add_test(suite, "entry contains a timestamp", test_audit_log_contains_timestamp_brackets);

    return suite;
}
