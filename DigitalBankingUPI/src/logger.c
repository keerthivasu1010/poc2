/**
 * @file logger.c
 * @brief Thread-safe timestamped application logger implementation.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>
#include "logger.h"

#define LOGGER_FILE "database/app.log"

static pthread_mutex_t g_logMutex = PTHREAD_MUTEX_INITIALIZER;
static LogLevel g_minLevel = LOG_LEVEL_INFO;

static const char *level_name(LogLevel level)
{
    switch (level)
    {
        case LOG_LEVEL_DEBUG:
            return "DEBUG";
        case LOG_LEVEL_INFO:
            return "INFO";
        case LOG_LEVEL_WARN:
            return "WARNING";
        case LOG_LEVEL_ERROR:
            return "ERROR";
        case LOG_LEVEL_FATAL:
            return "FATAL";
        default:
            return "UNKNOWN";
    }
}

void logger_set_level(LogLevel level)
{
    if ((level >= LOG_LEVEL_DEBUG) && (level <= LOG_LEVEL_FATAL))
    {
        g_minLevel = level;
    }
}

void logger_log(LogLevel level, const char *fmt, ...)
{
    time_t now;
    struct tm tmBuf;
    const struct tm *tmInfo;
    char timeBuf[32];
    unsigned long threadId;
    FILE *logFile;
    va_list args;

    if ((level < g_minLevel) || (fmt == NULL))
    {
        return;
    }

    now = time(NULL);
    tmInfo = localtime_r(&now, &tmBuf);

    if ((tmInfo == NULL) ||
        (strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", tmInfo) == 0U))
    {
        (void)snprintf(timeBuf, sizeof(timeBuf), "unknown-time");
    }

    /*
     * pthread_t is implementation-defined and should not be printed
     * directly with an integer format specifier. Casting to unsigned
     * long is suitable for the POSIX/Linux target used by this project.
     */
    threadId = (unsigned long)pthread_self();

    (void)pthread_mutex_lock(&g_logMutex);

    (void)fprintf(stderr,
                  "[%s] [%s] [THREAD:%lu] ",
                  timeBuf,
                  level_name(level),
                  threadId);

    va_start(args, fmt);
    (void)vfprintf(stderr, fmt, args);
    va_end(args);

    (void)fprintf(stderr, "\n");
    (void)fflush(stderr);

    /*
     * Mirror diagnostic logs to a file for persistent debugging and
     * error tracing. Failure to open the log file must not terminate
     * the banking application.
     */
    logFile = fopen(LOGGER_FILE, "a");
    if (logFile != NULL)
    {
        (void)fprintf(logFile,
                      "[%s] [%s] [THREAD:%lu] ",
                      timeBuf,
                      level_name(level),
                      threadId);

        va_start(args, fmt);
        (void)vfprintf(logFile, fmt, args);
        va_end(args);

        (void)fprintf(logFile, "\n");
        (void)fflush(logFile);
        (void)fclose(logFile);
    }

    (void)pthread_mutex_unlock(&g_logMutex);
}
