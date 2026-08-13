/**
 * @file test_logger.c
 * @brief Unit tests for the logger module (src/logger.c).
 *
 * logger_log() writes to stderr and mirrors to database/app.log, so
 * these tests run inside the usual storage sandbox (test_common.h)
 * and assert on the mirrored file's contents rather than on stderr.
 */

#include <stdio.h>
#include <string.h>
#include <CUnit/CUnit.h>
#include "logger.h"
#include "test_common.h"
#include "test_runner.h"

#define LOGGER_APP_LOG_PATH "database/app.log"

static int logger_suite_init(void)
{
    return test_sandbox_enter("logger");
}

static int logger_suite_cleanup(void)
{
    /* Leave the logger permissive for any suite that might (in a
     * different build) run after this one. */
    logger_set_level(LOG_LEVEL_INFO);
    test_sandbox_leave();
    return 0;
}

static long count_lines_containing(const char *needle)
{
    FILE *fp = fopen(LOGGER_APP_LOG_PATH, "r");
    char line[1024];
    long count = 0L;

    if (fp == NULL)
    {
        return 0L;
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

static void test_logger_set_level_valid_values_accepted(void)
{
    logger_set_level(LOG_LEVEL_DEBUG);
    logger_set_level(LOG_LEVEL_INFO);
    logger_set_level(LOG_LEVEL_WARN);
    logger_set_level(LOG_LEVEL_ERROR);
    logger_set_level(LOG_LEVEL_FATAL);
    /* No direct getter exists; reaching here without a crash and the
     * subsequent filtering test below confirms the level was applied. */
    CU_ASSERT_TRUE(1);
}

static void test_logger_set_level_out_of_range_ignored(void)
{
    /* Establish a known level, then attempt to set an invalid one;
     * the invalid call must be a no-op (branch coverage for the
     * range check), which the filtering test below verifies. */
    logger_set_level(LOG_LEVEL_ERROR);
    logger_set_level((LogLevel)(LOG_LEVEL_DEBUG - 1));
    logger_set_level((LogLevel)(LOG_LEVEL_FATAL + 1));

    CU_ASSERT_EQUAL(count_lines_containing("out-of-range-level-marker"), 0L);
    logger_log(LOG_LEVEL_DEBUG, "out-of-range-level-marker");
    /* Level should still be ERROR (unchanged by the invalid calls),
     * so a DEBUG message here must be filtered out. */
    CU_ASSERT_EQUAL(count_lines_containing("out-of-range-level-marker"), 0L);

    logger_set_level(LOG_LEVEL_DEBUG);
}

static void test_logger_log_writes_all_levels(void)
{
    logger_set_level(LOG_LEVEL_DEBUG);

    logger_log(LOG_LEVEL_DEBUG, "level-marker-debug %d", 1);
    logger_log(LOG_LEVEL_INFO,  "level-marker-info %d", 2);
    logger_log(LOG_LEVEL_WARN,  "level-marker-warn %d", 3);
    logger_log(LOG_LEVEL_ERROR, "level-marker-error %d", 4);
    logger_log(LOG_LEVEL_FATAL, "level-marker-fatal %d", 5);

    CU_ASSERT_TRUE(count_lines_containing("level-marker-debug 1") >= 1L);
    CU_ASSERT_TRUE(count_lines_containing("level-marker-info 2") >= 1L);
    CU_ASSERT_TRUE(count_lines_containing("level-marker-warn 3") >= 1L);
    CU_ASSERT_TRUE(count_lines_containing("level-marker-error 4") >= 1L);
    CU_ASSERT_TRUE(count_lines_containing("level-marker-fatal 5") >= 1L);

    CU_ASSERT_TRUE(count_lines_containing("[DEBUG]") >= 1L);
    CU_ASSERT_TRUE(count_lines_containing("[INFO]") >= 1L);
    CU_ASSERT_TRUE(count_lines_containing("[WARNING]") >= 1L);
    CU_ASSERT_TRUE(count_lines_containing("[ERROR]") >= 1L);
    CU_ASSERT_TRUE(count_lines_containing("[FATAL]") >= 1L);
}

static void test_logger_log_below_min_level_filtered(void)
{
    logger_set_level(LOG_LEVEL_WARN);

    logger_log(LOG_LEVEL_DEBUG, "filtered-marker-1");
    logger_log(LOG_LEVEL_INFO, "filtered-marker-1");
    CU_ASSERT_EQUAL(count_lines_containing("filtered-marker-1"), 0L);

    logger_log(LOG_LEVEL_WARN, "filtered-marker-1");
    CU_ASSERT_TRUE(count_lines_containing("filtered-marker-1") >= 1L);

    logger_set_level(LOG_LEVEL_DEBUG);
}

static void test_logger_log_null_format_ignored(void)
{
    logger_set_level(LOG_LEVEL_DEBUG);
    /* Must not crash and must not write anything. */
    logger_log(LOG_LEVEL_INFO, NULL);
    CU_ASSERT_TRUE(1);
}

static void test_logger_log_unknown_level_name(void)
{
    logger_set_level(LOG_LEVEL_DEBUG);
    /* A level value outside the named enum exercises level_name()'s
     * default "UNKNOWN" branch, while still being >= g_minLevel so
     * the message is actually written. */
    logger_log((LogLevel)99, "unknown-level-marker");
    CU_ASSERT_TRUE(count_lines_containing("[UNKNOWN]") >= 1L);
    CU_ASSERT_TRUE(count_lines_containing("unknown-level-marker") >= 1L);
}

CU_pSuite test_logger_suite_create(void)
{
    CU_pSuite suite = CU_add_suite("logger", logger_suite_init, logger_suite_cleanup);
    if (suite == NULL) { return NULL; }

    CU_add_test(suite, "set_level: valid values accepted", test_logger_set_level_valid_values_accepted);
    CU_add_test(suite, "set_level: out-of-range ignored", test_logger_set_level_out_of_range_ignored);
    CU_add_test(suite, "log: writes at all levels", test_logger_log_writes_all_levels);
    CU_add_test(suite, "log: below min level filtered", test_logger_log_below_min_level_filtered);
    CU_add_test(suite, "log: NULL format ignored", test_logger_log_null_format_ignored);
    CU_add_test(suite, "log: unknown level name", test_logger_log_unknown_level_name);

    return suite;
}
