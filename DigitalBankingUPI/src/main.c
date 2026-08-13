/**
 * @file main.c
 * @brief Entry point and menu-driven UI for the Digital Banking &
 *        UPI Transaction Security Platform.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include "bank.h"
#include "auth.h"
#include "transaction.h"
#include "integrity.h"
#include "storage.h"
#include "audit.h"
#include "account.h"
#include "admin.h"
#include "logger.h"

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

/**
 * @brief Read a menu choice. Returns the parsed integer choice, or
 *        INT_MIN if stdin could not be read (e.g. EOF), which the
 *        caller treats as "exit this menu" to avoid spinning forever
 *        on a closed input stream.
 */
static int read_menu_choice(void)
{
    char line[16];
    if (read_line(line, sizeof(line)) != 0)
    {
        return INT_MIN;
    }
    return atoi(line);
}

static void print_main_menu(void)
{
    printf("\n=====================================\n");
    printf(" Digital Banking & UPI Platform\n");
    printf("=====================================\n");
    printf(" 1. Register\n");
    printf(" 2. Login\n");
    printf(" 3. Exit\n");
    printf("=====================================\n");
    printf("Choice: ");
}

static void print_dashboard_menu(const char *username)
{
    printf("\n=====================================\n");
    printf(" Welcome, %s\n", username);
    printf("=====================================\n");
    printf(" 1. Check Balance\n");
    printf(" 2. Transfer Money\n");
    printf(" 3. Transaction History\n");
    printf(" 4. Verify Transaction Integrity\n");
    printf(" 5. Change Password/PIN\n");
    printf(" 6. Deposit Funds\n");
    printf(" 7. Logout\n");
    printf("=====================================\n");
    printf("Choice: ");
}

static void run_dashboard(Session *session)
{
    int running = 1;

    while (running != 0)
    {
        int choice;

        print_dashboard_menu(session->currentUser.username);
        choice = read_menu_choice();

        if (choice == INT_MIN)
        {
            printf("\nInput stream closed. Logging out.\n");
            (void)audit_log(session->currentUser.username, "forced logout: input stream closed");
            session->isLoggedIn = 0;
            break;
        }

        switch (choice)
        {
            case 1:
            {
                User fresh;
                if (storage_find_user(session->currentUser.username, &fresh) == 1)
                {
                    session->currentUser = fresh;
                    printf("\nCurrent balance: %.2f\n", fresh.balance);
                }
                else
                {
                    printf("\nCould not retrieve balance.\n");
                }
                break;
            }
            case 2:
            {
                char receiver[MAX_UPI_LEN];
                char amountStr[32];
                double amount;
                int rc;

                printf("\nReceiver UPI ID (e.g. name@digitalbank, name@okhdfcbank, name@ybl): ");
                if (read_line(receiver, sizeof(receiver)) != 0)
                {
                    printf("Input error.\n");
                    break;
                }
                printf("Amount: ");
                if (read_line(amountStr, sizeof(amountStr)) != 0)
                {
                    printf("Input error.\n");
                    break;
                }
                amount = atof(amountStr);

                rc = transaction_transfer(session->currentUser.username, receiver, amount);
                switch (rc)
                {
                    case 0:
                    {
                        User fresh;
                        if (storage_find_user(session->currentUser.username, &fresh) == 1)
                        {
                            session->currentUser = fresh;
                        }
                        break;
                    }
                    case -1: printf("Invalid transfer request.\n"); break;
                    case -2: printf("Sender account not found.\n"); break;
                    case -3: printf("Receiver account not found.\n"); break; /* unused: kept for backward compatibility */
                    case -4: printf("Insufficient balance.\n"); break;
                    case -6: printf("Invalid UPI ID format. Expected something like name@bank.\n"); break;
                    default: printf("Transfer failed due to a system error.\n"); break;
                }
                break;
            }
            case 3:
                (void)transaction_show_history(session->currentUser.username);
                break;
            case 4:
                (void)integrity_verify_user_transactions(session->currentUser.username);
                break;
            case 5:
                (void)account_change_credentials(session);
                break;
            case 6:
                (void)account_deposit_funds(session);
                break;
            case 7:
                printf("\nLogging out...\n");
                (void)audit_log(session->currentUser.username, "logout");
                session->isLoggedIn = 0;
                running = 0;
                break;
            default:
                printf("\nInvalid choice. Please try again.\n");
                break;
        }
    }
}

int main(void)
{
    int running = 1;
    Session session;

    memset(&session, 0, sizeof(session));

    LOG_INFO("Digital Banking & UPI Platform starting up");

    if (storage_init() != 0)
    {
        LOG_ERROR("Fatal: could not initialise storage.");
        fprintf(stderr, "Fatal: could not initialise storage.\n");
        return EXIT_FAILURE;
    }
    if (admin_ensure_default_account() != 0)
    {
        LOG_WARN("Could not verify/create administrator account.");
        fprintf(stderr, "Warning: could not verify/create administrator account.\n");
    }
    (void)audit_log("SYSTEM", "application started");
    LOG_INFO("Startup complete; entering main menu loop");

    while (running != 0)
    {
        int choice;

        print_main_menu();
        choice = read_menu_choice();

        if (choice == INT_MIN)
        {
            printf("\nInput stream closed. Exiting.\n");
            (void)audit_log("SYSTEM", "application exit: input stream closed");
            LOG_INFO("Shutting down: input stream closed");
            break;
        }

        switch (choice)
        {
            case 1:
                (void)registration_register();
                break;
            case 2:
                if (login_authenticate(&session) == 0)
                {
                    if (session.currentUser.isAdmin != 0)
                    {
                        admin_run_panel(session.currentUser.username);
                        session.isLoggedIn = 0;
                    }
                    else
                    {
                        run_dashboard(&session);
                    }
                }
                break;
            case 3:
                printf("\nThank you for using Digital Banking & UPI Platform. Goodbye!\n");
                (void)audit_log("SYSTEM", "application exit");
                LOG_INFO("Shutting down: normal exit selected by user");
                running = 0;
                break;
            default:
                printf("\nInvalid choice. Please try again.\n");
                break;
        }
    }

    return EXIT_SUCCESS;
}
