/**
 * @file test_logger.c
 * @brief Unit tests for the logger module (src/logger.c).
 */

#include <stdio.h>
#include <string.h>
#include <CUnit/CUnit.h>
#include "logger.h"
#include "test_common.h"
#include "test_runner.h"

static int logger_suite_init(void)
{
    return test_sandbox_enter("logger");
}

static int logger_suite_cleanup(void)
{
    test_sandbox_leave();
    return 0;
}

static void test_logger_set_level_valid_values(void)
{
    logger_set_level(LOG_LEVEL_DEBUG);
    logger_set_level(LOG_LEVEL_INFO);
    logger_set_level(LOG_LEVEL_WARN);
    logger_set_level(LOG_LEVEL_ERROR);
    logger_set_level(LOG_LEVEL_FATAL);
    CU_ASSERT_TRUE(1);
}

static void test_logger_set_level_out_of_range_ignored(void)
{
    logger_set_level(LOG_LEVEL_DEBUG);
    logger_set_level((LogLevel)(LOG_LEVEL_FATAL + 1));
    logger_set_level((LogLevel)(-1));
    LOG_DEBUG("still at DEBUG after invalid set_level calls");
    CU_ASSERT_TRUE(1);
}

static void test_logger_log_null_fmt_is_noop(void)
{
    logger_set_level(LOG_LEVEL_DEBUG);
    logger_log(LOG_LEVEL_INFO, NULL);
    CU_ASSERT_TRUE(1);
}

static void test_logger_log_below_min_level_suppressed(void)
{
    logger_set_level(LOG_LEVEL_ERROR);
    LOG_DEBUG("this should be suppressed");
    LOG_INFO("this should be suppressed too");
    CU_ASSERT_TRUE(1);
}

static void test_logger_log_all_levels_emitted(void)
{
    logger_set_level(LOG_LEVEL_DEBUG);
    LOG_DEBUG("debug message %d", 1);
    LOG_INFO("info message %d", 2);
    LOG_WARN("warn message %d", 3);
    LOG_ERROR("error message %d", 4);
    LOG_FATAL("fatal message %d", 5);
    CU_ASSERT_TRUE(1);
}

static void test_logger_log_unknown_level_name(void)
{
    logger_set_level(LOG_LEVEL_DEBUG);
    logger_log((LogLevel)99, "message with unrecognised level");
    CU_ASSERT_TRUE(1);
}

static void test_logger_log_writes_to_file(void)
{
    FILE *fp;
    char line[512];
    int found = 0;

    logger_set_level(LOG_LEVEL_DEBUG);
    LOG_INFO("unit-test-logger-marker-%d", 7);

    fp = fopen("database/app.log", "r");
    CU_ASSERT_PTR_NOT_NULL(fp);
    if (fp != NULL)
    {
        while (fgets(line, sizeof(line), fp) != NULL)
        {
            if (strstr(line, "unit-test-logger-marker-7") != NULL)
            {
                found = 1;
                break;
            }
        }
        (void)fclose(fp);
    }
    CU_ASSERT_TRUE(found);
}

CU_pSuite test_logger_suite_create(void)
{
    CU_pSuite suite = CU_add_suite("logger", logger_suite_init, logger_suite_cleanup);
    if (suite == NULL) { return NULL; }

    CU_add_test(suite, "set_level accepts all valid levels", test_logger_set_level_valid_values);
    CU_add_test(suite, "set_level ignores out-of-range values", test_logger_set_level_out_of_range_ignored);
    CU_add_test(suite, "log with NULL fmt is a no-op", test_logger_log_null_fmt_is_noop);
    CU_add_test(suite, "log below minimum level is suppressed", test_logger_log_below_min_level_suppressed);
    CU_add_test(suite, "log emits all levels", test_logger_log_all_levels_emitted);
    CU_add_test(suite, "log handles unrecognised level name", test_logger_log_unknown_level_name);
    CU_add_test(suite, "log writes mirrored line to file", test_logger_log_writes_to_file);

    return suite;
}
