/**
 * @file logger.h
 * @brief Thread-safe timestamped application logger.
 *
 * Diagnostic logging is written to stderr and, when available,
 * mirrored to database/app.log. The logger includes timestamp,
 * log level and POSIX thread ID.
 */

#ifndef LOGGER_H
#define LOGGER_H

typedef enum
{
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO  = 1,
    LOG_LEVEL_WARN  = 2,
    LOG_LEVEL_ERROR = 3,
    LOG_LEVEL_FATAL = 4
} LogLevel;

/**
 * @brief Set the minimum level that will be emitted.
 */
void logger_set_level(LogLevel level);

/**
 * @brief Write a timestamped, thread-safe log message.
 *
 * Format:
 * [YYYY-MM-DD HH:MM:SS] [LEVEL] [THREAD:<id>] message
 */
void logger_log(LogLevel level, const char *fmt, ...);

#define LOG_DEBUG(...) logger_log(LOG_LEVEL_DEBUG, __VA_ARGS__)
#define LOG_INFO(...)  logger_log(LOG_LEVEL_INFO,  __VA_ARGS__)
#define LOG_WARN(...)  logger_log(LOG_LEVEL_WARN,  __VA_ARGS__)
#define LOG_ERROR(...) logger_log(LOG_LEVEL_ERROR, __VA_ARGS__)
#define LOG_FATAL(...) logger_log(LOG_LEVEL_FATAL, __VA_ARGS__)

#endif /* LOGGER_H */
