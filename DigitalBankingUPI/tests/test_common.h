/**
 * @file test_common.h
 * @brief Shared helpers for unit tests that exercise the file-backed
 *        storage layer (src/storage.c uses paths relative to the
 *        current working directory, e.g. "database/users.dat").
 *
 * Each suite that touches storage calls test_sandbox_enter() with a
 * suite-unique name in its CUnit suite-init callback and
 * test_sandbox_leave() in its suite-cleanup callback. This creates a
 * fresh, isolated "database/" directory per suite so tests never
 * interfere with each other or with a developer's real database/.
 */

#ifndef TEST_COMMON_H
#define TEST_COMMON_H

/**
 * @brief Create (or reuse) an isolated scratch directory named
 *        "sandbox_<name>" under the current directory, chdir into
 *        it, and initialise fresh users/transactions/audit files.
 *
 * @param name Suite-unique subdirectory name (no slashes).
 * @return 0 on success, -1 on failure.
 */
int test_sandbox_enter(const char *name);

/**
 * @brief Return to the directory that was current before the most
 *        recent test_sandbox_enter() call.
 */
void test_sandbox_leave(void);

/**
 * @brief Redirect stdin to read from an in-memory buffer of
 *        newline-separated input lines, for testing functions that
 *        interactively prompt via fgets(stdin).
 *
 * @param data NUL-terminated string; the function copies it, so the
 *             caller's buffer/literal need not outlive the call.
 * @return 0 on success, -1 on failure.
 */
int test_feed_stdin(const char *data);

/**
 * @brief Restore the real stdin after a prior test_feed_stdin() call
 *        and free the associated scratch buffer.
 */
void test_restore_stdin(void);

#endif /* TEST_COMMON_H */
