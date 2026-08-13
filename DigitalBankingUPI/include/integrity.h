/**
 * @file integrity.h
 * @brief Transaction integrity verification interface.
 *
 * Recomputes the SHA-256 digest of a transaction's canonical
 * plaintext representation and compares it against the digest
 * stored at write time, allowing detection of tampering with the
 * transactions.dat file.
 */

#ifndef INTEGRITY_H
#define INTEGRITY_H

#include "transaction.h"

/**
 * @brief Compute the canonical SHA-256 integrity hash for a
 *        transaction's logical fields.
 *
 * @param sender    Sender username.
 * @param receiver  Receiver username.
 * @param amount    Transfer amount.
 * @param timestamp Timestamp string.
 * @param outHash   Output buffer, at least 65 bytes.
 * @return 0 on success, -1 on invalid arguments.
 */
int integrity_compute_hash(const char *sender,
                            const char *receiver,
                            double      amount,
                            const char *timestamp,
                            char        outHash[65]);

/**
 * @brief Verify every stored transaction for a given user and print
 *        a Verified / Tampered report to stdout.
 *
 * @param username Username whose transactions should be checked.
 * @return Number of transactions checked, or -1 on error.
 */
int integrity_verify_user_transactions(const char *username);

#endif /* INTEGRITY_H */
