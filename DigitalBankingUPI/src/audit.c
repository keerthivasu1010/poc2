/**
 * @file audit.c
 * @brief Append-only audit log writer.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include "audit.h"
#include "bank.h"

/*
 * Multiple threads may append to the audit log concurrently (e.g.
 * one thread processing a transfer while another handles a login).
 * A dedicated mutex keeps each log line's fopen/fprintf/fclose
 * sequence atomic so lines from different threads are never
 * interleaved or lost. This is separate from storage.c's mutex
 * since audit_log() is frequently called *while already holding*
 * the storage lock (e.g. from inside transaction_transfer()'s
 * critical section) as well as on its own; keeping it independent
 * avoids coupling the two modules' locking together.
 */
static pthread_mutex_t g_auditMutex = PTHREAD_MUTEX_INITIALIZER;

int audit_log(const char *username, const char *event)
{
    FILE *fp;
    time_t now;
    struct tm tmBuf;
    const struct tm *tmInfo;
    char timeBuf[32];
    int result;
    const char *who = (username != NULL) ? username : "SYSTEM";
    const char *what = (event != NULL) ? event : "";

    now = time(NULL);
    /* localtime_r() (rather than localtime()) is used because this
     * function may now be called concurrently from multiple threads;
     * plain localtime() returns a pointer to internal static storage
     * shared by every caller, which is a data race under threading. */
    tmInfo = localtime_r(&now, &tmBuf);
    if (tmInfo == NULL)
    {
        return -1;
    }
    if (strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", tmInfo) == 0U)
    {
        return -1;
    }

    (void)pthread_mutex_lock(&g_auditMutex);

    fp = fopen(AUDIT_LOG_PATH, "a");
    if (fp == NULL)
    {
        perror("audit_log: fopen");
        (void)pthread_mutex_unlock(&g_auditMutex);
        return -1;
    }

    result = (fprintf(fp, "[%s] user=%s event=%s\n", timeBuf, who, what) < 0) ? -1 : 0;

    (void)fclose(fp);
    (void)pthread_mutex_unlock(&g_auditMutex);
    return result;
}
