/**
 * @file admin.h
 * @brief Administrator panel: list users, freeze/unfreeze accounts,
 *        and clear login lockouts.
 */

#ifndef ADMIN_H
#define ADMIN_H

/**
 * @brief Ensure a default administrator account exists.
 *
 * Called once at startup. If no user with isAdmin set is found, a
 * bootstrap admin account (DEFAULT_ADMIN_USERNAME /
 * DEFAULT_ADMIN_PASSWORD / DEFAULT_ADMIN_PIN, see bank.h) is created
 * so the admin panel is reachable on a fresh install.
 *
 * @return 0 on success (including "admin already exists"), -1 on
 *         storage failure.
 */
int admin_ensure_default_account(void);

/**
 * @brief Run the interactive administrator menu loop until the admin
 *        chooses to log out.
 *
 * @param adminUsername Username of the authenticated administrator,
 *                       used for audit logging of admin actions.
 */
void admin_run_panel(const char *adminUsername);

#endif /* ADMIN_H */
