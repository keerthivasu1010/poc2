/**
 * @file audit.h
 * @brief Append-only audit logging interface.
 *
 * Every login, logout, registration, transfer, integrity check and
 * significant error is recorded to database/audit.log with a
 * timestamp for later forensic review.
 */

#ifndef AUDIT_H
#define AUDIT_H

/**
 * @brief Append a single line to the audit log, prefixed with the
 *        current local timestamp.
 *
 * @param username Username associated with the event, or "SYSTEM"
 *                 if not tied to a specific user.
 * @param event    Short human-readable event description.
 * @return 0 on success, -1 on I/O error.
 */
int audit_log(const char *username, const char *event);

#endif /* AUDIT_H */
