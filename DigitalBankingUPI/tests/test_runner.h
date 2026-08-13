/**
 * @file test_runner.h
 * @brief Declarations for each test suite's creation function, used
 *        by tests/test_runner.c to register every suite with CUnit.
 */

#ifndef TEST_RUNNER_H
#define TEST_RUNNER_H

#include <CUnit/CUnit.h>

CU_pSuite test_sha256_suite_create(void);
CU_pSuite test_aes_suite_create(void);
CU_pSuite test_storage_suite_create(void);
CU_pSuite test_auth_suite_create(void);
CU_pSuite test_transaction_suite_create(void);
CU_pSuite test_integrity_suite_create(void);
CU_pSuite test_account_suite_create(void);
CU_pSuite test_admin_suite_create(void);
CU_pSuite test_audit_suite_create(void);
CU_pSuite test_stress_suite_create(void);
CU_pSuite test_concurrency_suite_create(void);
CU_pSuite test_logger_suite_create(void);
CU_pSuite test_coverage_extra_suite_create(void);

#endif /* TEST_RUNNER_H */
