/**
 * @file auth.h
 * @brief Registration and login (authentication) interface.
 */

#ifndef AUTH_H
#define AUTH_H

#include "bank.h"

/**
 * @brief Interactively register a new user via stdin prompts.
 *
 * Reads username, password and PIN, validates them, derives a
 * SHA-256 credential hash, assigns a UPI ID, and persists the new
 * user record with a starting balance.
 *
 * @return 0 on success, -1 on validation failure or storage error.
 */
int registration_register(void);

/**
 * @brief Interactively authenticate a user via stdin prompts.
 *
 * @param outSession [out] Populated with the authenticated user's
 *                   data and marked logged-in on success.
 * @return 0 on success, -1 on failure (bad credentials, I/O error).
 */
int login_authenticate(Session *outSession);

#endif /* AUTH_H */
