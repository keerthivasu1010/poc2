/**
 * @file admin.c
 * @brief Administrator panel implementation.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include "admin.h"
#include "bank.h"
#include "sha256.h"
#include "storage.h"
#include "audit.h"

static int read_line(char *buf, size_t bufSize)
{
    size_t len;

    if (fgets(buf, (int)bufSize, stdin) == NULL)
    {
        return -1;
    }

    len = strlen(buf);

    /* If the buffer was filled exactly and the last character read
     * is not a newline, the input line was longer than the buffer
     * (or exactly filled it, leaving the newline unread). Drain the
     * remainder of the line so it cannot leak into the next prompt
     * as spurious input. */
    if ((len == (bufSize - 1U)) && (buf[len - 1U] != '\n'))
    {
        int c;
        do
        {
            c = getchar();
        } while ((c != '\n') && (c != EOF));
    }

    buf[strcspn(buf, "\r\n")] = '\0';
    return 0;
}

static int read_menu_choice(void)
{
    char line[16];
    if (read_line(line, sizeof(line)) != 0)
    {
        return INT_MIN;
    }
    return atoi(line);
}

typedef struct
{
    int adminExists;
} AdminScanContext;

static void admin_scan_visitor(const User *user, void *userData)
{
    AdminScanContext *ctx = (AdminScanContext *)userData;
    if (user->isAdmin != 0)
    {
        ctx->adminExists = 1;
    }
}

/* Original body, renamed to *_impl; see the wrapper below for why
 * the "does an admin already exist?" scan and the "create one"
 * write are locked together as one atomic unit. */
static int admin_ensure_default_account_impl(void)
{
    AdminScanContext ctx;
    User admin;
    char credential[128];

    ctx.adminExists = 0;

    if (storage_for_each_user(admin_scan_visitor, &ctx) < 0)
    {
        return -1;
    }

    if (ctx.adminExists != 0)
    {
        return 0;
    }

    memset(&admin, 0, sizeof(admin));
    strncpy(admin.username, DEFAULT_ADMIN_USERNAME, sizeof(admin.username) - 1U);
    strncpy(admin.upiID, "admin@digitalbank", sizeof(admin.upiID) - 1U);
    admin.balance = 0.0;
    admin.isAdmin = 1;
    admin.isFrozen = 0;
    admin.failedAttempts = 0;
    admin.lockedUntilEpoch = 0L;

    (void)snprintf(credential, sizeof(credential), "%s:%s",
                    DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_PIN);
    if (sha256_hash_string(credential, admin.passwordHash) != 0)
    {
        return -1;
    }
    memset(credential, 0, sizeof(credential));

    if (storage_add_user(&admin) != 0)
    {
        return -1;
    }

    printf("\n[SETUP] No administrator account found. Created default admin:\n");
    printf("        username=%s password=%s pin=%s\n",
           DEFAULT_ADMIN_USERNAME, DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_PIN);
    printf("        Please change these credentials immediately after logging in.\n");

    (void)audit_log("SYSTEM", "default admin account created");

    return 0;
}

int admin_ensure_default_account(void)
{
    int result;

    storage_lock();
    result = admin_ensure_default_account_impl();
    storage_unlock();

    return result;
}

static void print_admin_menu(void)
{
    printf("\n=====================================\n");
    printf(" Administrator Panel\n");
    printf("=====================================\n");
    printf(" 1. List All Users\n");
    printf(" 2. Freeze Account\n");
    printf(" 3. Unfreeze Account\n");
    printf(" 4. Clear Login Lockout\n");
    printf(" 5. Logout\n");
    printf("=====================================\n");
    printf("Choice: ");
}

static void list_users_visitor(const User *user, void *userData)
{
    int *count = (int *)userData;
    const char *lockState = (user->lockedUntilEpoch > 0L) ? "LOCKED" : "ok";
    const char *frozenState = (user->isFrozen != 0) ? "FROZEN" : "active";
    const char *roleState = (user->isAdmin != 0) ? "admin" : "user";

    (*count)++;
    printf("  %2d) %-20s role=%-5s status=%-6s login=%-6s balance=%.2f failedAttempts=%d\n",
           *count, user->username, roleState, frozenState, lockState,
           user->balance, user->failedAttempts);
}

static void handle_list_users(void)
{
    int count = 0;
    printf("\n--- All Registered Users ---\n");
    if (storage_for_each_user(list_users_visitor, &count) < 0)
    {
        printf("Could not read user store.\n");
        return;
    }
    if (count == 0)
    {
        printf("No users registered.\n");
    }
}

/* Original body, renamed to *_impl; see the thin wrapper below that
 * runs it under storage_lock()/storage_unlock() so a concurrent
 * freeze/unfreeze and, say, a login attempt for the same account
 * can't race on the user record. */
static void handle_set_frozen_impl(const char *adminUsername, int freeze)
{
    char target[MAX_USERNAME_LEN];
    User user;
    char logMsg[96];

    printf("\nUsername to %s: ", freeze ? "freeze" : "unfreeze");
    if (read_line(target, sizeof(target)) != 0)
    {
        printf("Input error.\n");
        return;
    }

    if (storage_find_user(target, &user) != 1)
    {
        printf("User not found.\n");
        return;
    }

    if (user.isAdmin != 0)
    {
        printf("Refusing to freeze an administrator account.\n");
        return;
    }

    user.isFrozen = freeze ? 1 : 0;

    if (storage_update_user(&user) != 0)
    {
        printf("Failed to update account status.\n");
        return;
    }

    printf("Account '%s' is now %s.\n", target, freeze ? "FROZEN" : "active");
    (void)snprintf(logMsg, sizeof(logMsg), "admin %s account %s",
                    freeze ? "froze" : "unfroze", target);
    (void)audit_log(adminUsername, logMsg);
}

static void handle_set_frozen(const char *adminUsername, int freeze)
{
    storage_lock();
    handle_set_frozen_impl(adminUsername, freeze);
    storage_unlock();
}

/* Original body, renamed to *_impl; see handle_set_frozen() above
 * for why the public-facing caller takes the storage lock for the
 * whole read-then-write operation. */
static void handle_clear_lockout_impl(const char *adminUsername)
{
    char target[MAX_USERNAME_LEN];
    User user;
    char logMsg[96];

    printf("\nUsername to clear lockout for: ");
    if (read_line(target, sizeof(target)) != 0)
    {
        printf("Input error.\n");
        return;
    }

    if (storage_find_user(target, &user) != 1)
    {
        printf("User not found.\n");
        return;
    }

    user.failedAttempts = 0;
    user.lockedUntilEpoch = 0L;

    if (storage_update_user(&user) != 0)
    {
        printf("Failed to clear lockout.\n");
        return;
    }

    printf("Lockout cleared for '%s'.\n", target);
    (void)snprintf(logMsg, sizeof(logMsg), "admin cleared lockout for %s", target);
    (void)audit_log(adminUsername, logMsg);
}

static void handle_clear_lockout(const char *adminUsername)
{
    storage_lock();
    handle_clear_lockout_impl(adminUsername);
    storage_unlock();
}

void admin_run_panel(const char *adminUsername)
{
    int running = 1;

    if (adminUsername == NULL)
    {
        return;
    }

    while (running != 0)
    {
        int choice;

        print_admin_menu();
        choice = read_menu_choice();

        if (choice == INT_MIN)
        {
            printf("\nInput stream closed. Logging out of admin panel.\n");
            (void)audit_log(adminUsername, "forced admin logout: input stream closed");
            break;
        }

        switch (choice)
        {
            case 1:
                handle_list_users();
                break;
            case 2:
                handle_set_frozen(adminUsername, 1);
                break;
            case 3:
                handle_set_frozen(adminUsername, 0);
                break;
            case 4:
                handle_clear_lockout(adminUsername);
                break;
            case 5:
                printf("\nLogging out of admin panel...\n");
                (void)audit_log(adminUsername, "admin logout");
                running = 0;
                break;
            default:
                printf("\nInvalid choice. Please try again.\n");
                break;
        }
    }
}
