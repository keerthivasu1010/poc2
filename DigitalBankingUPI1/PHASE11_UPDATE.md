# Phase 11 + Build/Test Separation Update

## Timestamping and Logging

The project now provides a thread-safe diagnostic logger with:

- Timestamp: `YYYY-MM-DD HH:MM:SS`
- Log levels: DEBUG, INFO, WARNING, ERROR, FATAL
- POSIX thread ID
- Console logging through `stderr`
- Persistent logging to `database/app.log`
- Mutex protection for concurrent logger calls
- Thread-safe `localtime_r()`
- Graceful handling if the log file cannot be opened

Example:

`[2026-08-10 21:45:32] [INFO] [THREAD:12345] Login successful`

## Test/Coverage Separation

### `make test`
Runs CUnit unit/integration tests only.

- No `--coverage`
- No `.gcda`
- No `.gcno`
- No `.gcov`

### `make coverage`
Runs the actual banking application using:

`tests/coverage_input.txt`

It does not invoke CUnit. Coverage instrumentation is temporary and the generated `.gcda`, `.gcno`, and `.gcov` files are removed after the report is generated.

Coverage report:

`build/coverage/summary.txt`

## Commands

```bash
make clean
make
make test
make coverage
make valgrind
make cppcheck
make misra
```

`make coverage` requires `tests/coverage_input.txt`.
