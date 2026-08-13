/**
 * @file test_runner.c
 * @brief Entry point for the CUnit test suite. Registers every
 *        module's test suite and runs them all, printing results
 *        grouped by suite ("== <suite> tests ==") with one
 *        "[ OK ]"/"[FAIL]" line per test, followed by a final
 *        pass/fail banner.
 *
 * Build/run via `make test` (see Makefile), which compiles this
 * file together with every test_ source file under tests/ and every
 * module under src/ except main.c (which supplies its own main()),
 * then links against libcunit and executes the resulting binary.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <CUnit/CUnit.h>
#include <CUnit/TestRun.h>
#include "test_runner.h"

/*
 * Some of the code under test (registration, login, transfers,
 * deposits, stress/concurrency loops that run hundreds of
 * transfers, ...) prints its own interactive prompts/status lines
 * via printf() as part of normal operation. Left alone that makes
 * the test output extremely long (thousands of lines for the
 * stress/concurrency suites alone). So application stdout is
 * silenced for the duration of each individual test's body, and
 * restored right before printing that test's own "[ OK ]"/"[FAIL]"
 * result line, keeping the log to just the suite headers, one line
 * per test, and (for any failure) the failing assertion's file/line.
 */
static int savedStdoutFd = -1;
static int stdoutSilenced = 0;

static int silence_stdout(void)
{
    int devNull;

    fflush(stdout);
    savedStdoutFd = dup(STDOUT_FILENO);
    if (savedStdoutFd < 0)
    {
        return -1;
    }

    devNull = open("/dev/null", O_WRONLY);
    if (devNull < 0)
    {
        return -1;
    }

    (void)dup2(devNull, STDOUT_FILENO);
    close(devNull);
    return 0;
}

static void restore_stdout(void)
{
    if (savedStdoutFd < 0)
    {
        return;
    }
    fflush(stdout);
    (void)dup2(savedStdoutFd, STDOUT_FILENO);
    close(savedStdoutFd);
    savedStdoutFd = -1;
}

static void on_suite_start(const CU_pSuite pSuite)
{
    printf("\n== %s tests ==\n",
           (pSuite != NULL && pSuite->pName != NULL) ? pSuite->pName : "?");
}

static void on_test_start(const CU_pTest pTest, const CU_pSuite pSuite)
{
    (void)pTest;
    (void)pSuite;

    if (silence_stdout() == 0)
    {
        stdoutSilenced = 1;
    }
}

static void on_test_complete(const CU_pTest pTest, const CU_pSuite pSuite,
                              const CU_pFailureRecord pFailureList)
{
    const char *testName;

    (void)pSuite;

    if (stdoutSilenced)
    {
        restore_stdout();
        stdoutSilenced = 0;
    }

    testName = (pTest != NULL && pTest->pName != NULL) ? pTest->pName : "?";

    if (pFailureList == NULL)
    {
        printf("  [ OK ] %s\n", testName);
    }
    else
    {
        CU_pFailureRecord rec;

        printf("  [FAIL] %s\n", testName);
        for (rec = pFailureList; rec != NULL; rec = rec->pNext)
        {
            printf("         %s:%u  %s\n",
                   (rec->strFileName != NULL) ? rec->strFileName : "?",
                   rec->uiLineNumber,
                   (rec->strCondition != NULL) ? rec->strCondition : "?");
        }
    }
}

/*
 * CU_BRM_SILENT still leaves CUnit's own suite-complete/all-tests-complete
 * handlers wired to print things like the "Run Summary" table. Since we
 * print our own summary banner below, these are overridden as no-ops so
 * that table doesn't also show up.
 */
static void on_suite_complete(const CU_pSuite pSuite, const CU_pFailureRecord pFailureList)
{
    (void)pSuite;
    (void)pFailureList;
}

static void on_all_tests_complete(const CU_pFailureRecord pFailureList)
{
    (void)pFailureList;
}

int main(void)
{
    unsigned int failures;

    if (CU_initialize_registry() != CUE_SUCCESS)
    {
        fprintf(stderr, "Failed to initialise CUnit registry.\n");
        return EXIT_FAILURE;
    }

    if ((test_sha256_suite_create() == NULL) ||
        (test_aes_suite_create() == NULL) ||
        (test_storage_suite_create() == NULL) ||
        (test_auth_suite_create() == NULL) ||
        (test_transaction_suite_create() == NULL) ||
        (test_integrity_suite_create() == NULL) ||
        (test_account_suite_create() == NULL) ||
        (test_admin_suite_create() == NULL) ||
        (test_audit_suite_create() == NULL) ||
        (test_logger_suite_create() == NULL) ||
        (test_stress_suite_create() == NULL) ||
        (test_concurrency_suite_create() == NULL))
    {
        fprintf(stderr, "Failed to register one or more test suites: %s\n",
                CU_get_error_msg());
        CU_cleanup_registry();
        return EXIT_FAILURE;
    }

    printf("===========================================\n");
    printf(" Digital Banking Platform - Unit/Integration Tests\n");
    printf("===========================================\n");

    CU_set_suite_start_handler(on_suite_start);
    CU_set_test_start_handler(on_test_start);
    CU_set_test_complete_handler(on_test_complete);
    CU_set_suite_complete_handler(on_suite_complete);
    CU_set_all_test_complete_handler(on_all_tests_complete);

    /*
     * CU_run_all_tests() is CUnit's low-level registry runner (what
     * CU_basic_run_tests() itself wraps). Using it directly, instead
     * of the Basic interface, means our handlers above stay in
     * effect instead of being replaced by Basic's own run-mode
     * reporting -- Basic re-registers its own suite/test-complete
     * handlers internally when CU_basic_run_tests() is called.
     */
    (void)CU_run_all_tests();

    failures = CU_get_number_of_failures();

    printf("\n===========================================\n");
    printf(failures == 0U ? " ALL TESTS PASSED\n" : " SOME TESTS FAILED\n");
    printf("===========================================\n");

    CU_cleanup_registry();

    return (failures == 0U) ? EXIT_SUCCESS : EXIT_FAILURE;
}
