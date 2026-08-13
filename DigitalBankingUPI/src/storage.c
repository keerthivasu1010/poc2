/**
 * @file storage.c
 * @brief File-backed persistence for users and transactions.
 *
 * Records are stored as one '|'-delimited line per record. This is a
 * simple, dependency-free format suitable for a demonstration
 * platform; a production system would use a real database with
 * proper transactions and locking.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include "storage.h"

#define TMP_USERS_PATH "database/users.dat.tmp"

/*
 * Process-wide, re-entrant (recursive) lock guarding every file
 * access made through this module. This is what makes it safe for
 * multiple threads to call storage_* functions concurrently, and
 * lets callers (transaction_transfer(), login lockout bookkeeping,
 * admin freeze/unfreeze, etc.) group several storage_* calls into
 * one atomic critical section via storage_lock()/storage_unlock().
 *
 * Lazily initialised with pthread_once() so no explicit "threading
 * init" step is required before the first storage_* call, whether
 * or not the process ever actually spawns a second thread.
 */
static pthread_mutex_t g_storageMutex;
static pthread_once_t  g_storageMutexOnce = PTHREAD_ONCE_INIT;

static void storage_mutex_init(void)
{
    pthread_mutexattr_t attr;

    (void)pthread_mutexattr_init(&attr);
    (void)pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    (void)pthread_mutex_init(&g_storageMutex, &attr);
    (void)pthread_mutexattr_destroy(&attr);
}

void storage_lock(void)
{
    (void)pthread_once(&g_storageMutexOnce, storage_mutex_init);
    (void)pthread_mutex_lock(&g_storageMutex);
}

void storage_unlock(void)
{
    (void)pthread_mutex_unlock(&g_storageMutex);
}

static FILE *open_or_create(const char *path, const char *mode)
{
    FILE *fp = fopen(path, mode);
    return fp;
}

static int storage_init_impl(void)
{
    struct stat st;
    FILE *fp;

    if (stat("database", &st) != 0)
    {
        if (mkdir("database", 0700) != 0)
        {
            perror("storage_init: mkdir");
            return -1;
        }
    }

    fp = fopen(USERS_DB_PATH, "a");
    if (fp == NULL)
    {
        perror("storage_init: users.dat");
        return -1;
    }
    (void)fclose(fp);

    fp = fopen(TRANSACTIONS_DB_PATH, "a");
    if (fp == NULL)
    {
        perror("storage_init: transactions.dat");
        return -1;
    }
    (void)fclose(fp);

    fp = fopen(AUDIT_LOG_PATH, "a");
    if (fp == NULL)
    {
        perror("storage_init: audit.log");
        return -1;
    }
    (void)fclose(fp);

    return 0;
}

/**
 * @brief Parse one line of the users.dat format into a User struct.
 * Format: username|passwordHash|upiID|balance|isAdmin|isFrozen|failedAttempts|lockedUntilEpoch
 *
 * For backward compatibility with older 4-field records (before the
 * admin/lockout fields were introduced), any missing trailing fields
 * default to 0.
 */
static int parse_user_line(const char *line, User *outUser)
{
    char buf[MAX_LINE_LEN];
    const char *token;
    char *saveptr = NULL;

    if ((line == NULL) || (outUser == NULL))
    {
        return -1;
    }

    memset(outUser, 0, sizeof(*outUser));

    strncpy(buf, line, sizeof(buf) - 1U);
    buf[sizeof(buf) - 1U] = '\0';

    token = strtok_r(buf, "|", &saveptr);
    if (token == NULL) { return -1; }
    strncpy(outUser->username, token, sizeof(outUser->username) - 1U);
    outUser->username[sizeof(outUser->username) - 1U] = '\0';

    token = strtok_r(NULL, "|", &saveptr);
    if (token == NULL) { return -1; }
    strncpy(outUser->passwordHash, token, sizeof(outUser->passwordHash) - 1U);
    outUser->passwordHash[sizeof(outUser->passwordHash) - 1U] = '\0';

    token = strtok_r(NULL, "|", &saveptr);
    if (token == NULL) { return -1; }
    strncpy(outUser->upiID, token, sizeof(outUser->upiID) - 1U);
    outUser->upiID[sizeof(outUser->upiID) - 1U] = '\0';

    token = strtok_r(NULL, "|", &saveptr);
    if (token == NULL) { return -1; }
    outUser->balance = atof(token);

    /* Remaining fields are optional for backward compatibility. */
    token = strtok_r(NULL, "|", &saveptr);
    outUser->isAdmin = (token != NULL) ? atoi(token) : 0;

    token = strtok_r(NULL, "|", &saveptr);
    outUser->isFrozen = (token != NULL) ? atoi(token) : 0;

    token = strtok_r(NULL, "|", &saveptr);
    outUser->failedAttempts = (token != NULL) ? atoi(token) : 0;

    token = strtok_r(NULL, "|\r\n", &saveptr);
    outUser->lockedUntilEpoch = (token != NULL) ? atol(token) : 0L;

    return 0;
}

static int write_user_line(FILE *fp, const User *user)
{
    return (fprintf(fp, "%s|%s|%s|%.2f|%d|%d|%d|%ld\n",
                     user->username, user->passwordHash, user->upiID, user->balance,
                     user->isAdmin, user->isFrozen, user->failedAttempts,
                     user->lockedUntilEpoch) < 0) ? -1 : 0;
}

static int storage_find_user_impl(const char *username, User *outUser)
{
    FILE *fp;
    char line[MAX_LINE_LEN];
    int found = 0;

    if ((username == NULL) || (outUser == NULL))
    {
        return -1;
    }

    fp = open_or_create(USERS_DB_PATH, "r");
    if (fp == NULL)
    {
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL)
    {
        User candidate;
        if (parse_user_line(line, &candidate) != 0)
        {
            continue;
        }
        if (strcmp(candidate.username, username) == 0)
        {
            *outUser = candidate;
            found = 1;
            break;
        }
    }

    (void)fclose(fp);
    return found;
}

static int storage_find_user_by_upi_impl(const char *upiId, User *outUser)
{
    FILE *fp;
    char line[MAX_LINE_LEN];
    int found = 0;

    if ((upiId == NULL) || (outUser == NULL))
    {
        return -1;
    }

    fp = open_or_create(USERS_DB_PATH, "r");
    if (fp == NULL)
    {
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL)
    {
        User candidate;
        if (parse_user_line(line, &candidate) != 0)
        {
            continue;
        }
        if (strcmp(candidate.upiID, upiId) == 0)
        {
            *outUser = candidate;
            found = 1;
            break;
        }
    }

    (void)fclose(fp);
    return found;
}

static int storage_add_user_impl(const User *user)
{
    FILE *fp;
    User existing;

    if (user == NULL)
    {
        return -1;
    }

    if (storage_find_user(user->username, &existing) == 1)
    {
        return -1; /* duplicate username */
    }

    fp = fopen(USERS_DB_PATH, "a");
    if (fp == NULL)
    {
        perror("storage_add_user: fopen");
        return -1;
    }

    if (write_user_line(fp, user) != 0)
    {
        (void)fclose(fp);
        return -1;
    }

    (void)fclose(fp);
    return 0;
}

static int storage_update_user_impl(const User *user)
{
    FILE *in;
    FILE *out;
    char line[MAX_LINE_LEN];
    int updated = 0;

    if (user == NULL)
    {
        return -1;
    }

    in = fopen(USERS_DB_PATH, "r");
    if (in == NULL)
    {
        return -1;
    }

    out = fopen(TMP_USERS_PATH, "w");
    if (out == NULL)
    {
        (void)fclose(in);
        return -1;
    }

    while (fgets(line, sizeof(line), in) != NULL)
    {
        User candidate;
        if (parse_user_line(line, &candidate) == 0)
        {
            const User *toWrite = &candidate;
            if (strcmp(candidate.username, user->username) == 0)
            {
                toWrite = user;
                updated = 1;
            }
            if (write_user_line(out, toWrite) != 0)
            {
                (void)fclose(in);
                (void)fclose(out);
                (void)remove(TMP_USERS_PATH);
                return -1;
            }
        }
    }

    (void)fclose(in);
    (void)fclose(out);

    if (updated == 0)
    {
        (void)remove(TMP_USERS_PATH);
        return -1;
    }

    if (remove(USERS_DB_PATH) != 0)
    {
        return -1;
    }
    if (rename(TMP_USERS_PATH, USERS_DB_PATH) != 0)
    {
        return -1;
    }

    return 0;
}

static int storage_update_balance_impl(const char *username, double newBalance)
{
    User user;

    if (username == NULL)
    {
        return -1;
    }

    if (storage_find_user(username, &user) != 1)
    {
        return -1;
    }

    user.balance = newBalance;
    return storage_update_user(&user);
}

static int storage_for_each_user_impl(UserVisitor visitor, void *userData)
{
    FILE *fp;
    char line[MAX_LINE_LEN];
    int count = 0;

    if (visitor == NULL)
    {
        return -1;
    }

    fp = open_or_create(USERS_DB_PATH, "r");
    if (fp == NULL)
    {
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL)
    {
        User user;
        if (parse_user_line(line, &user) == 0)
        {
            visitor(&user, userData);
            count++;
        }
    }

    (void)fclose(fp);
    return count;
}

/**
 * @brief Parse one line of the transactions.dat format.
 * Format: sender|receiver|amount|timestamp|encryptedData|hash
 */
static int parse_txn_line(const char *line, Transaction *outTxn)
{
    char buf[MAX_LINE_LEN];
    const char *token;
    char *saveptr = NULL;

    if ((line == NULL) || (outTxn == NULL))
    {
        return -1;
    }

    strncpy(buf, line, sizeof(buf) - 1U);
    buf[sizeof(buf) - 1U] = '\0';

    token = strtok_r(buf, "|", &saveptr);
    if (token == NULL) { return -1; }
    strncpy(outTxn->sender, token, sizeof(outTxn->sender) - 1U);
    outTxn->sender[sizeof(outTxn->sender) - 1U] = '\0';

    token = strtok_r(NULL, "|", &saveptr);
    if (token == NULL) { return -1; }
    strncpy(outTxn->receiver, token, sizeof(outTxn->receiver) - 1U);
    outTxn->receiver[sizeof(outTxn->receiver) - 1U] = '\0';

    token = strtok_r(NULL, "|", &saveptr);
    if (token == NULL) { return -1; }
    outTxn->amount = atof(token);

    token = strtok_r(NULL, "|", &saveptr);
    if (token == NULL) { return -1; }
    strncpy(outTxn->timestamp, token, sizeof(outTxn->timestamp) - 1U);
    outTxn->timestamp[sizeof(outTxn->timestamp) - 1U] = '\0';

    token = strtok_r(NULL, "|", &saveptr);
    if (token == NULL) { return -1; }
    strncpy(outTxn->encryptedData, token, sizeof(outTxn->encryptedData) - 1U);
    outTxn->encryptedData[sizeof(outTxn->encryptedData) - 1U] = '\0';

    token = strtok_r(NULL, "|\r\n", &saveptr);
    if (token == NULL) { return -1; }
    strncpy(outTxn->hash, token, sizeof(outTxn->hash) - 1U);
    outTxn->hash[sizeof(outTxn->hash) - 1U] = '\0';

    return 0;
}

static int storage_add_transaction_impl(const Transaction *txn)
{
    FILE *fp;

    if (txn == NULL)
    {
        return -1;
    }

    fp = fopen(TRANSACTIONS_DB_PATH, "a");
    if (fp == NULL)
    {
        perror("storage_add_transaction: fopen");
        return -1;
    }

    if (fprintf(fp, "%s|%s|%.2f|%s|%s|%s\n",
                txn->sender, txn->receiver, txn->amount,
                txn->timestamp, txn->encryptedData, txn->hash) < 0)
    {
        (void)fclose(fp);
        return -1;
    }

    (void)fclose(fp);
    return 0;
}

static int storage_for_each_transaction_impl(TransactionVisitor visitor, void *userData)
{
    FILE *fp;
    char line[MAX_LINE_LEN];
    int count = 0;

    if (visitor == NULL)
    {
        return -1;
    }

    fp = open_or_create(TRANSACTIONS_DB_PATH, "r");
    if (fp == NULL)
    {
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL)
    {
        Transaction txn;
        if (parse_txn_line(line, &txn) == 0)
        {
            visitor(&txn, userData);
            count++;
        }
    }

    (void)fclose(fp);
    return count;
}

/*
 * ---------------------------------------------------------------
 * Thread-safe public wrappers.
 *
 * Every function below simply takes the process-wide storage lock,
 * delegates to the original (now-static "_impl") implementation
 * above, and releases the lock. Because g_storageMutex is a
 * recursive mutex, it is safe for one wrapper to call another
 * public storage_* function internally (e.g. storage_add_user_impl()
 * calling storage_find_user()) without deadlocking.
 *
 * Callers that need several of these calls to happen as a single
 * atomic unit (e.g. transaction_transfer()'s check-then-debit-then-
 * credit sequence) should wrap that whole sequence in their own
 * storage_lock()/storage_unlock() pair; see transaction.c.
 * ---------------------------------------------------------------
 */

int storage_init(void)
{
    int result;
    storage_lock();
    result = storage_init_impl();
    storage_unlock();
    return result;
}

int storage_find_user(const char *username, User *outUser)
{
    int result;
    storage_lock();
    result = storage_find_user_impl(username, outUser);
    storage_unlock();
    return result;
}

int storage_find_user_by_upi(const char *upiId, User *outUser)
{
    int result;
    storage_lock();
    result = storage_find_user_by_upi_impl(upiId, outUser);
    storage_unlock();
    return result;
}

int storage_add_user(const User *user)
{
    int result;
    storage_lock();
    result = storage_add_user_impl(user);
    storage_unlock();
    return result;
}

int storage_update_user(const User *user)
{
    int result;
    storage_lock();
    result = storage_update_user_impl(user);
    storage_unlock();
    return result;
}

int storage_update_balance(const char *username, double newBalance)
{
    int result;
    storage_lock();
    result = storage_update_balance_impl(username, newBalance);
    storage_unlock();
    return result;
}

int storage_for_each_user(UserVisitor visitor, void *userData)
{
    int result;
    storage_lock();
    result = storage_for_each_user_impl(visitor, userData);
    storage_unlock();
    return result;
}

int storage_add_transaction(const Transaction *txn)
{
    int result;
    storage_lock();
    result = storage_add_transaction_impl(txn);
    storage_unlock();
    return result;
}

int storage_for_each_transaction(TransactionVisitor visitor, void *userData)
{
    int result;
    storage_lock();
    result = storage_for_each_transaction_impl(visitor, userData);
    storage_unlock();
    return result;
}
