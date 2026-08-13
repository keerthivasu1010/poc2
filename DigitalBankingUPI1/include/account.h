/**
 * @file account.h
 * @brief Self-service account management: changing password/PIN and
 *        depositing funds into one's own account.
 */

#ifndef ACCOUNT_H
#define ACCOUNT_H

#include "bank.h"

/**
 * @brief Interactively change the current user's password and PIN.
 *
 * Re-verifies the user's current password/PIN before accepting a new
 * one, applying the same validation rules used at registration.
 *
 * @param session Active session; on success, session->currentUser is
 *                updated to reflect the new stored credential hash.
 * @return 0 on success, -1 on validation failure, re-authentication
 *         failure, or storage error.
 */
int account_change_credentials(Session *session);

/**
 * @brief Interactively deposit funds ("cash deposit") into the
 *        current user's own account.
 *
 * This is not a peer-to-peer UPI transfer (no receiver account is
 * involved), so it is not recorded in transactions.dat; it is
 * recorded only in the audit log and reflected in the user's balance.
 *
 * @param session Active session; on success, session->currentUser is
 *                updated with the new balance.
 * @return 0 on success, -1 on invalid amount or storage error.
 */
int account_deposit_funds(Session *session);

#endif /* ACCOUNT_H */
