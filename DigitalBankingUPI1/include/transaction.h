/**
 * @file transaction.h
 * @brief UPI-style fund transfer transaction interface.
 */

#ifndef TRANSACTION_H
#define TRANSACTION_H

#include "bank.h"

#define MAX_TIMESTAMP_LEN   40
#define MAX_ENCRYPTED_LEN   256

/**
 * @brief Represents a single funds-transfer transaction as persisted
 *        to transactions.dat.
 *
 * encryptedData holds the hex-encoded AES-128 ciphertext of a
 * descriptive payload ("sender|receiver|amount|timestamp").
 * hash holds the hex-encoded SHA-256 digest computed over the
 * plaintext record, used later for integrity verification.
 */
typedef struct
{
    char   sender[MAX_USERNAME_LEN];
    char   receiver[MAX_UPI_LEN];
    double amount;
    char   timestamp[MAX_TIMESTAMP_LEN];
    char   encryptedData[MAX_ENCRYPTED_LEN];
    char   hash[65];
} Transaction;

/**
 * @brief Check whether a string is a syntactically valid UPI ID of
 *        the general form "<handle>@<psp>" (e.g. "name@digitalbank",
 *        "name@okhdfcbank", "name@ybl", "name@paytm"). Any PSP/bank
 *        handle suffix is accepted -- this only validates shape, not
 *        which PSP it is.
 *
 * Rules enforced:
 *  - Exactly one '@' character, with at least one character before
 *    and after it.
 *  - Only letters, digits, '.', '-', and '_' are allowed (plus the
 *    single '@').
 *  - Overall length must be between 3 and MAX_UPI_LEN-1 characters.
 *
 * @param upiId String to validate.
 * @return 1 if the string looks like a valid UPI ID, 0 otherwise.
 */
int upi_is_valid_format(const char *upiId);

/**
 * @brief Validate and execute a fund transfer from an authenticated
 *        sender to a receiver identified by UPI ID, encrypt the
 *        transaction payload, compute its integrity hash, persist
 *        it, and write an audit log entry.
 *
 * The receiver UPI ID does not need to belong to a user registered
 * on this platform -- exactly like real-world UPI, a payment can be
 * addressed to any syntactically valid UPI ID at any bank/PSP. If it
 * resolves to a local account, that account's balance is credited;
 * otherwise the transfer is recorded as an outbound payment to an
 * external UPI handle and only the sender's balance is debited.
 *
 * @param sender      Username of the authenticated sender (must exist).
 * @param receiverUpi UPI ID of the receiving account; any validly
 *                     formatted UPI ID is accepted (e.g.
 *                     "name@digitalbank", "name@okhdfcbank",
 *                     "name@ybl"), whether or not it belongs to a
 *                     user registered on this platform.
 * @param amount      Amount to transfer; must be > 0 and <= sender balance.
 * @return 0 on success, negative error code on failure:
 *         -1 invalid arguments, -2 sender not found, -4 insufficient
 *         balance, -5 storage failure, -6 malformed UPI ID.
 */
int transaction_transfer(const char *sender, const char *receiverUpi, double amount);

/**
 * @brief Display the transaction history for a given user
 *        (as sender or receiver) to stdout.
 *
 * @param username Username whose history should be displayed.
 * @return Number of matching transactions displayed, or -1 on error.
 */
int transaction_show_history(const char *username);

#endif /* TRANSACTION_H */
