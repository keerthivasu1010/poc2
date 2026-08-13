/**
 * @file storage.h
 * @brief Persistent storage interface for users and transactions.
 *
 * Records are stored as fixed, delimiter-separated text lines
 * ('|' separated) inside the database/ directory. All file access
 * is centralised here so that other modules never touch raw file
 * handles directly.
 */

#ifndef STORAGE_H
#define STORAGE_H

#include "bank.h"
#include "transaction.h"

/**
 * @brief Ensure the database/ directory and empty data files exist.
 * @return 0 on success, -1 on failure.
 */
int storage_init(void);

/**
 * @brief Acquire the process-wide storage lock.
 *
 * The banking platform may now be driven by multiple threads at
 * once (see `bank_process_transfers_concurrently()` in
 * transaction.h and the `-pthread` build). Every public storage_*
 * function already takes this lock internally for the duration of
 * its own file access, so callers never need to call this directly
 * just to invoke a single storage_* function safely.
 *
 * Callers DO need to call this explicitly when a *sequence* of
 * storage_* calls must execute as one atomic unit (a "read, decide,
 * write" critical section) -- for example transferring funds (check
 * balance, then debit, then credit, then log) or updating a login
 * failure counter (read, increment, write). Without this, two
 * threads could interleave between the read and the write and lose
 * an update (a classic check-then-act race).
 *
 * The lock is re-entrant (recursive): the same thread may call
 * storage_lock() more than once (e.g. a caller locks, then calls a
 * storage_* function that locks again internally) as long as it
 * calls storage_unlock() the same number of times.
 */
void storage_lock(void);

/**
 * @brief Release the process-wide storage lock acquired by a
 *        matching storage_lock() call on the same thread.
 */
void storage_unlock(void);

/**
 * @brief Look up a user by username.
 *
 * @param username Username to search for.
 * @param outUser  [out] Populated on success.
 * @return 1 if found, 0 if not found, -1 on I/O error.
 */
int storage_find_user(const char *username, User *outUser);

/**
 * @brief Look up a user by UPI ID (e.g. "name@digitalbank",
 *        "name@okhdfcbank", "name@ybl", etc.).
 *
 * @param upiId   UPI ID to search for.
 * @param outUser [out] Populated on success.
 * @return 1 if found, 0 if not found, -1 on I/O error.
 */
int storage_find_user_by_upi(const char *upiId, User *outUser);

/**
 * @brief Append a new user record to users.dat.
 *
 * @param user User record to persist.
 * @return 0 on success, -1 on failure (including duplicate username).
 */
int storage_add_user(const User *user);

/**
 * @brief Persist an updated balance for an existing user.
 *
 * Rewrites the users database with the matching record updated.
 *
 * @param username Username whose balance should be updated.
 * @param newBalance New balance value.
 * @return 0 on success, -1 if user not found or on I/O error.
 */
int storage_update_balance(const char *username, double newBalance);

/**
 * @brief Persist a full updated user record (all fields), matched by
 *        username. Used for credential changes, admin actions
 *        (freeze/unfreeze), and login lockout bookkeeping.
 *
 * @param user Updated user record; user->username identifies which
 *             existing record to replace.
 * @return 0 on success, -1 if user not found or on I/O error.
 */
int storage_update_user(const User *user);

/**
 * @brief Callback type used by storage_for_each_user().
 * @param user     The user record read.
 * @param userData Opaque pointer passed through from the caller.
 */
typedef void (*UserVisitor)(const User *user, void *userData);

/**
 * @brief Iterate over every registered user in file order.
 *
 * @param visitor  Callback invoked once per user record.
 * @param userData Opaque pointer forwarded to the callback.
 * @return Number of records visited, or -1 on I/O error.
 */
int storage_for_each_user(UserVisitor visitor, void *userData);

/**
 * @brief Append a transaction record to transactions.dat.
 * @param txn Transaction to persist.
 * @return 0 on success, -1 on failure.
 */
int storage_add_transaction(const Transaction *txn);

/**
 * @brief Callback type used by storage_for_each_transaction().
 * @param txn      The transaction record read.
 * @param userData Opaque pointer passed through from the caller.
 */
typedef void (*TransactionVisitor)(const Transaction *txn, void *userData);

/**
 * @brief Iterate over every stored transaction in file order.
 *
 * @param visitor  Callback invoked once per transaction record.
 * @param userData Opaque pointer forwarded to the callback.
 * @return Number of records visited, or -1 on I/O error.
 */
int storage_for_each_transaction(TransactionVisitor visitor, void *userData);

#endif /* STORAGE_H */
