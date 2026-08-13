/**
 * @file test_concurrency.c
 * @brief Multithreading tests: drive storage.c, transaction.c, and
 *        audit.c from several pthreads at once and confirm the
 *        locking added in this pass (storage_lock()/storage_unlock(),
 *        the recursive mutex in storage.c, and the mutex in
 *        audit.c) prevents lost updates, corrupted records, and
 *        overdrafts under real concurrent access.
 */

#define _POSIX_C_SOURCE 200809L

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CUnit/CUnit.h>
#include "storage.h"
#include "transaction.h"
#include "audit.h"
#include "bank.h"
#include "test_common.h"
#include "test_runner.h"

#define CONCURRENCY_THREAD_COUNT      8
#define REGISTER_USERS_PER_THREAD     25
#define TRANSFER_ROUNDS_PER_THREAD    50
#define DEPOSIT_ROUNDS_PER_THREAD     50

static int concurrency_suite_init(void)
{
    return test_sandbox_enter("concurrency");
}

static int concurrency_suite_cleanup(void)
{
    test_sandbox_leave();
    return 0;
}

static void make_local_user(const char *username, double balance, User *outUser)
{
    memset(outUser, 0, sizeof(*outUser));
    strncpy(outUser->username, username, sizeof(outUser->username) - 1U);
    (void)snprintf(outUser->upiID, sizeof(outUser->upiID), "%s@digitalbank", username);
    strncpy(outUser->passwordHash, "deadbeefdeadbeefdeadbeefdeadbeef", sizeof(outUser->passwordHash) - 1U);
    outUser->balance = balance;
}

/* ------------------------------------------------------------------
 * Test 1: many threads registering distinct users concurrently.
 *
 * Every storage_add_user() call is independent (no shared record),
 * so this mainly exercises that concurrent appends to users.dat
 * never corrupt or drop a line, and that storage_for_each_user()
 * afterwards sees exactly the expected number of well-formed
 * records.
 * ------------------------------------------------------------------ */

typedef struct
{
    int threadIndex;
} RegisterThreadArg;

static void *register_thread_fn(void *arg)
{
    const RegisterThreadArg *targ = (const RegisterThreadArg *)arg;
    int i;

    for (i = 0; i < REGISTER_USERS_PER_THREAD; i++)
    {
        User u;
        char username[MAX_USERNAME_LEN];
        (void)snprintf(username, sizeof(username), "cu_%d_%d", targ->threadIndex, i);
        make_local_user(username, 100.0, &u);
        /* Not asserting inside a worker thread (CUnit's assertion
         * macros are not documented as thread-safe); instead every
         * thread just does the work, and the parent thread verifies
         * the resulting state after joining everyone. */
        (void)storage_add_user(&u);
    }

    return NULL;
}

typedef struct
{
    int count;
} CountVisitorCtx;

static void count_visitor(const User *user, void *userData)
{
    CountVisitorCtx *ctx = (CountVisitorCtx *)userData;
    (void)user;
    ctx->count++;
}

static void test_concurrent_registration_no_lost_or_corrupted_records(void)
{
    pthread_t threads[CONCURRENCY_THREAD_COUNT];
    RegisterThreadArg args[CONCURRENCY_THREAD_COUNT];
    CountVisitorCtx ctx;
    int t;

    for (t = 0; t < CONCURRENCY_THREAD_COUNT; t++)
    {
        args[t].threadIndex = t;
        CU_ASSERT_EQUAL(pthread_create(&threads[t], NULL, register_thread_fn, &args[t]), 0);
    }
    for (t = 0; t < CONCURRENCY_THREAD_COUNT; t++)
    {
        CU_ASSERT_EQUAL(pthread_join(threads[t], NULL), 0);
    }

    ctx.count = 0;
    CU_ASSERT_EQUAL(storage_for_each_user(count_visitor, &ctx),
                     CONCURRENCY_THREAD_COUNT * REGISTER_USERS_PER_THREAD);
    CU_ASSERT_EQUAL(ctx.count, CONCURRENCY_THREAD_COUNT * REGISTER_USERS_PER_THREAD);

    /* Spot-check a handful of the users are actually findable and
     * have a well-formed (non-corrupted) record. */
    {
        User found;
        CU_ASSERT_EQUAL(storage_find_user("cu_0_0", &found), 1);
        CU_ASSERT_DOUBLE_EQUAL(found.balance, 100.0, 0.001);
        CU_ASSERT_EQUAL(storage_find_user("cu_7_24", &found), 1);
        CU_ASSERT_DOUBLE_EQUAL(found.balance, 100.0, 0.001);
    }
}

/* ------------------------------------------------------------------
 * Test 2: many threads transferring funds concurrently between a
 * small, shared pool of accounts.
 *
 * This is the important test: transaction_transfer() reads a
 * balance, checks it, and writes a new balance. Without the
 * storage_lock()/storage_unlock() added around
 * transaction_transfer_impl() in this pass, concurrent transfers
 * touching the same account race on that read-modify-write and can
 * lose updates (money appears from nowhere or vanishes) or allow a
 * debit past a balance that a concurrent thread hasn't committed
 * yet (an overdraft). Because every transfer here moves money
 * between accounts already known to this platform, the sum of all
 * balances afterwards must equal the sum before, exactly, no matter
 * how the threads interleaved.
 * ------------------------------------------------------------------ */

#define POOL_ACCOUNT_COUNT 5
#define POOL_STARTING_BALANCE 10000.0

typedef struct
{
    int threadIndex;
} TransferThreadArg;

static void *transfer_thread_fn(void *arg)
{
    const TransferThreadArg *targ = (const TransferThreadArg *)arg;
    int i;
    unsigned int seed = (unsigned int)(targ->threadIndex * 7919 + 17);

    for (i = 0; i < TRANSFER_ROUNDS_PER_THREAD; i++)
    {
        int from = (int)(rand_r(&seed) % POOL_ACCOUNT_COUNT);
        int to;
        char sender[MAX_USERNAME_LEN];
        char receiverUpi[MAX_UPI_LEN];

        do
        {
            to = (int)(rand_r(&seed) % POOL_ACCOUNT_COUNT);
        } while (to == from);

        (void)snprintf(sender, sizeof(sender), "pool_%d", from);
        (void)snprintf(receiverUpi, sizeof(receiverUpi), "pool_%d@digitalbank", to);

        /* A small, fixed amount; some of these will be rejected for
         * insufficient balance depending on interleaving, and that's
         * fine -- transaction_transfer() itself decides that safely
         * under the lock. What matters is that accepted transfers
         * never lose or create money. */
        (void)transaction_transfer(sender, receiverUpi, 3.0);
    }

    return NULL;
}

static void test_concurrent_transfers_preserve_total_balance(void)
{
    pthread_t threads[CONCURRENCY_THREAD_COUNT];
    TransferThreadArg args[CONCURRENCY_THREAD_COUNT];
    int t;
    int a;
    double totalBefore = 0.0;
    double totalAfter = 0.0;

    for (a = 0; a < POOL_ACCOUNT_COUNT; a++)
    {
        User u;
        char username[MAX_USERNAME_LEN];
        (void)snprintf(username, sizeof(username), "pool_%d", a);
        make_local_user(username, POOL_STARTING_BALANCE, &u);
        CU_ASSERT_EQUAL(storage_add_user(&u), 0);
        totalBefore += POOL_STARTING_BALANCE;
    }

    for (t = 0; t < CONCURRENCY_THREAD_COUNT; t++)
    {
        args[t].threadIndex = t;
        CU_ASSERT_EQUAL(pthread_create(&threads[t], NULL, transfer_thread_fn, &args[t]), 0);
    }
    for (t = 0; t < CONCURRENCY_THREAD_COUNT; t++)
    {
        CU_ASSERT_EQUAL(pthread_join(threads[t], NULL), 0);
    }

    for (a = 0; a < POOL_ACCOUNT_COUNT; a++)
    {
        User found;
        char username[MAX_USERNAME_LEN];
        (void)snprintf(username, sizeof(username), "pool_%d", a);
        CU_ASSERT_EQUAL(storage_find_user(username, &found), 1);
        /* No account should ever have gone negative -- that would
         * mean a debit slipped through an interleaved, stale
         * balance check (an overdraft race). */
        CU_ASSERT_TRUE(found.balance >= 0.0);
        totalAfter += found.balance;
    }

    /* The pool is closed (every sender and receiver is one of the
     * pool accounts), so total funds must be conserved exactly
     * regardless of how many transfers succeeded or in what order
     * the threads ran. */
    CU_ASSERT_DOUBLE_EQUAL(totalAfter, totalBefore, 0.001);
}

/* ------------------------------------------------------------------
 * Test 3: many threads depositing into their own distinct accounts
 * concurrently via account-style read-modify-write on
 * storage_update_user(), driven directly through storage.c (the
 * same pattern account_deposit_funds() uses) to confirm no deposit
 * is lost when several threads hit *different* accounts at once.
 * ------------------------------------------------------------------ */

typedef struct
{
    int threadIndex;
} DepositThreadArg;

static void *deposit_thread_fn(void *arg)
{
    const DepositThreadArg *targ = (const DepositThreadArg *)arg;
    char username[MAX_USERNAME_LEN];
    int i;

    (void)snprintf(username, sizeof(username), "dep_%d", targ->threadIndex);

    for (i = 0; i < DEPOSIT_ROUNDS_PER_THREAD; i++)
    {
        /*
         * storage_lock()/storage_unlock() (exported from storage.h)
         * let a caller group a read + write into one atomic step,
         * exactly like account_deposit_funds_impl() does internally.
         * This test drives that same pattern directly to keep the
         * suite independent of interactive stdin plumbing.
         */
        User u;
        storage_lock();
        if (storage_find_user(username, &u) == 1)
        {
            u.balance += 1.0;
            (void)storage_update_user(&u);
        }
        storage_unlock();
    }

    return NULL;
}

static void test_concurrent_deposits_to_distinct_accounts_not_lost(void)
{
    pthread_t threads[CONCURRENCY_THREAD_COUNT];
    DepositThreadArg args[CONCURRENCY_THREAD_COUNT];
    int t;

    for (t = 0; t < CONCURRENCY_THREAD_COUNT; t++)
    {
        User u;
        char username[MAX_USERNAME_LEN];
        (void)snprintf(username, sizeof(username), "dep_%d", t);
        make_local_user(username, 0.0, &u);
        CU_ASSERT_EQUAL(storage_add_user(&u), 0);
    }

    for (t = 0; t < CONCURRENCY_THREAD_COUNT; t++)
    {
        args[t].threadIndex = t;
        CU_ASSERT_EQUAL(pthread_create(&threads[t], NULL, deposit_thread_fn, &args[t]), 0);
    }
    for (t = 0; t < CONCURRENCY_THREAD_COUNT; t++)
    {
        CU_ASSERT_EQUAL(pthread_join(threads[t], NULL), 0);
    }

    for (t = 0; t < CONCURRENCY_THREAD_COUNT; t++)
    {
        User found;
        char username[MAX_USERNAME_LEN];
        (void)snprintf(username, sizeof(username), "dep_%d", t);
        CU_ASSERT_EQUAL(storage_find_user(username, &found), 1);
        /* Every one of this thread's own DEPOSIT_ROUNDS_PER_THREAD
         * increments must be reflected -- none lost to a race with
         * another thread depositing into a *different* account. */
        CU_ASSERT_DOUBLE_EQUAL(found.balance, (double)DEPOSIT_ROUNDS_PER_THREAD, 0.001);
    }
}

/* ------------------------------------------------------------------
 * Test 4: many threads writing to the audit log concurrently. Every
 * line written must survive intact (no interleaved/corrupted lines,
 * none silently dropped).
 * ------------------------------------------------------------------ */

#define AUDIT_LINES_PER_THREAD 60

typedef struct
{
    int threadIndex;
} AuditThreadArg;

static void *audit_thread_fn(void *arg)
{
    const AuditThreadArg *targ = (const AuditThreadArg *)arg;
    int i;

    for (i = 0; i < AUDIT_LINES_PER_THREAD; i++)
    {
        char user[32];
        char event[64];
        (void)snprintf(user, sizeof(user), "audituser_%d", targ->threadIndex);
        (void)snprintf(event, sizeof(event), "concurrency test event %d", i);
        (void)audit_log(user, event);
    }

    return NULL;
}

static void test_concurrent_audit_logging_no_corrupted_lines(void)
{
    pthread_t threads[CONCURRENCY_THREAD_COUNT];
    AuditThreadArg args[CONCURRENCY_THREAD_COUNT];
    int t;
    FILE *fp;
    char line[512];
    int lineCount = 0;
    int malformedCount = 0;

    for (t = 0; t < CONCURRENCY_THREAD_COUNT; t++)
    {
        args[t].threadIndex = t;
        CU_ASSERT_EQUAL(pthread_create(&threads[t], NULL, audit_thread_fn, &args[t]), 0);
    }
    for (t = 0; t < CONCURRENCY_THREAD_COUNT; t++)
    {
        CU_ASSERT_EQUAL(pthread_join(threads[t], NULL), 0);
    }

    fp = fopen(AUDIT_LOG_PATH, "r");
    CU_ASSERT_PTR_NOT_NULL_FATAL(fp);

    while (fgets(line, sizeof(line), fp) != NULL)
    {
        lineCount++;
        /* Every well-formed line starts with "[" (the timestamp) and
         * contains "user=" and "event=". A corrupted, interleaved
         * write from two threads racing on the same fprintf() would
         * very likely break this shape. */
        if ((line[0] != '[') ||
            (strstr(line, "user=") == NULL) ||
            (strstr(line, "event=") == NULL))
        {
            malformedCount++;
        }
    }
    (void)fclose(fp);

    CU_ASSERT_EQUAL(malformedCount, 0);
    /* At least the lines this test wrote must be present (the file
     * may also contain earlier lines from storage_init(), etc., so
     * this is a lower bound, not an exact count). */
    CU_ASSERT_TRUE(lineCount >= (CONCURRENCY_THREAD_COUNT * AUDIT_LINES_PER_THREAD));
}

CU_pSuite test_concurrency_suite_create(void)
{
    CU_pSuite suite = CU_add_suite("concurrency", concurrency_suite_init, concurrency_suite_cleanup);
    if (suite == NULL)
    {
        return NULL;
    }

    if ((CU_add_test(suite, "concurrent registration: no lost/corrupted records",
                      test_concurrent_registration_no_lost_or_corrupted_records) == NULL) ||
        (CU_add_test(suite, "concurrent transfers: total balance conserved, no overdraft",
                      test_concurrent_transfers_preserve_total_balance) == NULL) ||
        (CU_add_test(suite, "concurrent deposits to distinct accounts: none lost",
                      test_concurrent_deposits_to_distinct_accounts_not_lost) == NULL) ||
        (CU_add_test(suite, "concurrent audit logging: no corrupted lines",
                      test_concurrent_audit_logging_no_corrupted_lines) == NULL))
    {
        return NULL;
    }

    return suite;
}
