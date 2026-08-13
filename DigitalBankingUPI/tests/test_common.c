/**
 * @file test_common.c
 * @brief Implementation of the test sandbox helper (see test_common.h).
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "test_common.h"
#include "storage.h"

static char savedCwd[1024];
static char activeSandboxPath[256] = "";
static FILE *originalStdin = NULL;
static char *feedBuffer = NULL;

int test_sandbox_enter(const char *name)
{
    char dirPath[256];

    if (name == NULL)
    {
        return -1;
    }

    if (getcwd(savedCwd, sizeof(savedCwd)) == NULL)
    {
        return -1;
    }

    (void)snprintf(dirPath, sizeof(dirPath), "sandbox_%s", name);
    (void)mkdir(dirPath, 0700);

    if (chdir(dirPath) != 0)
    {
        return -1;
    }

    /* Remember the sandbox path (relative to savedCwd) so
     * test_sandbox_leave() can remove it once the suite is done,
     * instead of leaving scratch database files/folders on disk. */
    (void)snprintf(activeSandboxPath, sizeof(activeSandboxPath), "%s", dirPath);

    /* Start each suite with a clean slate. */
    (void)remove(USERS_DB_PATH);
    (void)remove(TRANSACTIONS_DB_PATH);
    (void)remove(AUDIT_LOG_PATH);
    (void)rmdir("database");

    return storage_init();
}

void test_sandbox_leave(void)
{
    (void)chdir(savedCwd);

    /* Clean up the scratch sandbox_<name> directory (its database/
     * files and the folder itself) so test runs don't leave any
     * files or folders behind in the project tree. */
    if (activeSandboxPath[0] != '\0')
    {
        char filePath[300];

        (void)snprintf(filePath, sizeof(filePath), "%s/%s", activeSandboxPath, USERS_DB_PATH);
        (void)remove(filePath);
        (void)snprintf(filePath, sizeof(filePath), "%s/%s", activeSandboxPath, TRANSACTIONS_DB_PATH);
        (void)remove(filePath);
        (void)snprintf(filePath, sizeof(filePath), "%s/%s", activeSandboxPath, AUDIT_LOG_PATH);
        (void)remove(filePath);

        (void)snprintf(filePath, sizeof(filePath), "%s/database", activeSandboxPath);
        (void)rmdir(filePath);
        (void)rmdir(activeSandboxPath);

        activeSandboxPath[0] = '\0';
    }
}

int test_feed_stdin(const char *data)
{
    size_t len;
    FILE *fp;

    if (data == NULL)
    {
        return -1;
    }

    if (originalStdin == NULL)
    {
        originalStdin = stdin;
    }

    if (feedBuffer != NULL)
    {
        free(feedBuffer);
        feedBuffer = NULL;
    }

    len = strlen(data);
    feedBuffer = malloc(len + 1U);
    if (feedBuffer == NULL)
    {
        return -1;
    }
    memcpy(feedBuffer, data, len + 1U);

    fp = fmemopen(feedBuffer, len, "r");
    if (fp == NULL)
    {
        free(feedBuffer);
        feedBuffer = NULL;
        return -1;
    }

    if ((stdin != NULL) && (stdin != originalStdin))
    {
        (void)fclose(stdin);
    }

    stdin = fp;
    return 0;
}

void test_restore_stdin(void)
{
    if ((stdin != NULL) && (stdin != originalStdin))
    {
        (void)fclose(stdin);
    }

    if (originalStdin != NULL)
    {
        stdin = originalStdin;
    }

    if (feedBuffer != NULL)
    {
        free(feedBuffer);
        feedBuffer = NULL;
    }
}
