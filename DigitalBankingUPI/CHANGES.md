# CHANGES.md — Quality Hardening Pass

This document records every change made to the `DigitalBankingUPI` project
during this hardening pass (GCC/MISRA-oriented compilation, CPPCheck,
Valgrind, smoke testing, unit testing, integration testing).

**Scope note:** the original request text described a *Flight Management
System* (modules `flight`, `booking`, `waitlist`, `revenue`, `reports`,
binary `fms`). This repository is actually the **Digital Banking & UPI
Transaction Security Platform** (modules `account`, `admin`, `aes`, `audit`,
`auth`/`login`/`registration`, `integrity`, `sha256`, `storage`,
`transaction`, `history`, binary `bank`). The same quality bar (zero GCC
warnings, clean CPPCheck, clean Valgrind, full unit/integration tests,
build system, documentation) was applied to the real project instead of
fabricating unrelated flight-booking code.

No existing functionality, module interfaces, or the on-disk data format
were removed or changed. All changes are either bug fixes or additive
(new tests, new Makefile targets, new documentation).

---

## 1. Compiler warnings fixed

**Baseline:** compiling with
`gcc -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wunused-parameter -fanalyzer -Iinclude src/*.c -o bank`
produced **one** warning:

- `src/registration.c:169` — `-Wformat-truncation=`: the `snprintf()` that
  builds a user's UPI ID (`"<username>@digitalbank"`) could truncate for a
  username near the 29-character maximum, because `MAX_UPI_LEN` (40) was
  not large enough to hold `MAX_USERNAME_LEN - 1` (29) characters plus
  `"@digitalbank"` (12 characters) plus the terminating NUL (42 bytes
  needed).

  **Fix:** increased `MAX_UPI_LEN` in `include/bank.h` from `40` to `48`,
  documented the reasoning in a comment. Verified this does not affect the
  on-disk record format (fields are parsed with `strtok_r()` on a `'|'`
  delimiter, not fixed-width `sscanf()` conversions, so no other code
  depends on the old constant value).

**Result:** zero warnings, including under `-fanalyzer`, across `src/`
and the new `tests/` suite.

---

## 2. Functional bug fixed: unread trailing input on max-length lines

**Bug:** every interactive `read_line()` helper (duplicated in
`src/main.c`, `src/registration.c`, `src/login.c`, `src/account.c`,
`src/admin.c`) called `fgets(buf, (int)bufSize, stdin)` into a buffer
sized to exactly the field's maximum length (e.g. `username[30]` for a
29-character maximum username). When the user's input line was long
enough to completely fill the buffer, `fgets()` stops one byte before the
terminating newline, leaving that `'\n'` unread in the stdin stream. The
next prompt's `read_line()` call would then read that leftover, empty
line instead of the user's actual next answer — e.g. typing a full
29-character username at registration silently corrupted the following
password prompt into reading an empty string, which was then rejected as
"Invalid password." This was found by an automated unit test
(`test_stress.c`, boundary-length username case) rather than by manual
testing, since it only manifests exactly at the maximum valid input
length.

**Fix:** every `read_line()` implementation now detects when the buffer
was filled without capturing a trailing `'\n'` and drains the remainder
of the line via `getchar()` before returning, so no stray input can leak
into the next prompt. This preserves the existing function signature and
behavior for all normal-length input; it only changes behavior for the
previously-broken max-length-line case, making it now behave correctly.

Files changed: `src/main.c`, `src/registration.c`, `src/login.c`,
`src/account.c`, `src/admin.c`.

---

## 3. MISRA-C oriented improvements

The codebase was already close to MISRA-C style (explicit braces on every
`if`/`for`/`while`, `static` helper functions, header guards, no implicit
int, etc.), so this pass focused on the issues found above plus a review
against the checklist:

- **Fixed-width / explicit types:** already used throughout
  (`uint8_t`, `uint32_t`, `uint64_t` in `sha256.h`/`aes.h`).
- **Magic numbers:** the one meaningful magic-number risk found was the
  `MAX_UPI_LEN` sizing issue above; fixed with an explanatory comment
  rather than an unexplained constant bump.
- **Defensive programming / NULL checks:** every public function in
  `storage.c`, `transaction.c`, `integrity.c`, `account.c`, `admin.c`,
  `auth.c` was confirmed (via new unit tests) to reject `NULL` arguments
  rather than dereferencing them.
- **Buffer safety:** all string copies in the codebase already use
  `strncpy`/`snprintf` with explicit size limits and manual
  NUL-termination; the AES/SHA implementations use fixed-size internal
  buffers with capacity checks (`aes128_encrypt_buffer` returns `-1` on
  insufficient output capacity, verified by a new unit test).
- **Switch defaults:** all `switch` statements on menu choices already
  have a `default` case.
- **No dead code / duplicated logic** beyond the five duplicated
  `read_line()` helpers, which were intentionally left as separate
  `static` functions per file (their existing module boundaries) rather
  than refactored into a shared header, to avoid changing the project's
  file/module structure as instructed; each copy received the identical
  fix described in Section 2.

No behavior-changing MISRA "improvements" (e.g. converting `int` flags to
an `enum`, or restructuring the storage format) were made, since the
instructions were to preserve existing structure and behavior unless a
change was necessary to pass the listed checks.

---

## 4. CPPCheck static analysis

`cppcheck --enable=all --std=c11 --suppress=missingIncludeSystem -Iinclude src`
and
`cppcheck --enable=all --std=c11 --check-config --suppress=missingIncludeSystem -Iinclude src`

Both passes report **zero warnings** (style, performance, portability,
resource leak, null pointer, redundant assignment, unused variable/
function, shadow variable) on the current codebase, both before and after
the fixes above — the `MAX_UPI_LEN` truncation issue was a GCC
`-Wformat-truncation` finding, not a CPPCheck finding, so no CPPCheck
regressions were introduced or needed fixing. The same clean result holds
for the new `tests/` directory.

(`missingIncludeSystem` informational notes about standard library
headers not being found are suppressed, as documented in CPPCheck's own
output — these are expected in a sandboxed analysis environment without
CPPCheck's system header database and do not indicate any real issue.)

---

## 5. Valgrind memory analysis

`valgrind --leak-check=full --show-leak-kinds=all ./bank < tests/valgrind_input.txt`
and the same over `tests/smoke_input.txt`, and over the full CUnit test
binary (`./test_runner`), all report:

```
HEAP SUMMARY:
    in use at exit: 0 bytes in 0 blocks
All heap blocks were freed -- no leaks are possible
ERROR SUMMARY: 0 errors from 0 contexts
```

No leaks, double frees, invalid reads/writes, or use-after-free issues
were found — the existing code's consistent `fopen`/`fclose` pairing and
lack of dynamic (`malloc`) allocation in the core banking logic meant
there was nothing to fix here; the checks confirm this rather than
finding new bugs.

---

## 6. Smoke testing

`tests/smoke_input.txt` (new) drives a single interactive session through
every feature end-to-end: registration validation failures (short
username/password/PIN) → two successful registrations → a failed login
(wrong password) → a successful login → balance check → a local-to-local
UPI transfer → a transfer to a non-local UPI handle → a transfer that
exceeds the sender's balance (rejected) → transaction history → integrity
verification → credential change → funds deposit → an invalid menu choice
→ logout → admin login → list users → freeze/unfreeze/clear-lockout on
another account → an admin-side invalid menu choice → admin logout →
program exit. The run completes with exit code 0 and no crash, hang, or
invalid memory access.

`tests/valgrind_input.txt` (new) is a shorter, fully deterministic
variant of the same flow (no intentionally-invalid inputs) sized for fast
repeated Valgrind runs.

---

## 7. Unit tests (new)

Added a CUnit-based test suite under `tests/`, mapped to this project's
actual modules (see the scope note above):

- `tests/test_sha256.c` — FIPS-180-4 known-answer vectors (empty string,
  `"abc"`, the 56-byte multi-block vector), determinism, avalanche
  effect, NULL-argument handling, buffer-vs-string API parity,
  incremental vs. one-shot hashing equivalence.
- `tests/test_aes.c` — FIPS-197 Appendix B known-answer vector, buffer
  and hex-string round-trips, empty-plaintext round-trip, key
  sensitivity, NULL/invalid-argument handling, insufficient-output-buffer
  rejection, corrupted-ciphertext handling.
- `tests/test_storage.c` — add/find user, duplicate-username rejection,
  find-by-UPI, balance updates, full-record updates, missing-user error
  paths, iteration over users and transactions, NULL-argument handling,
  empty-store iteration.
- `tests/test_auth.c` — registration success/failure paths (invalid
  username/password/PIN, duplicate username, EOF-on-first-prompt), login
  success/failure paths (wrong password, unknown user, NULL session), and
  the brute-force lockout after `MAX_FAILED_LOGIN_ATTEMPTS`.
- `tests/test_transaction.c` — UPI ID format validation (valid and
  invalid shapes), local-to-local transfers, transfers to external UPI
  handles, invalid-argument/self-transfer/insufficient-balance/malformed-
  UPI/unknown-sender rejection, exact-balance transfers, transaction
  history counting.
- `tests/test_integrity.c` — hash determinism, sensitivity to amount
  changes, NULL-argument handling, verification of untampered
  transactions, and the no-transactions case.
- `tests/test_account.c` — credential change (success, wrong current
  credentials, invalid new password, not-logged-in), funds deposit
  (success, negative/zero amount rejection, not-logged-in).
- `tests/test_admin.c` — default admin bootstrap and idempotency, a full
  admin-panel session covering freeze/unfreeze/clear-lockout, refusal to
  freeze an administrator account, unknown-target handling, invalid menu
  choices, NULL-username and EOF handling.
- `tests/test_audit.c` — log-line appending, multiple appends, NULL
  username defaulting to `"SYSTEM"`, NULL event handling, timestamp
  presence.
- `tests/test_stress.c` — boundary-length usernames/passwords/PINs (at
  and just past each documented limit, including the max-length username
  case that surfaced the bug in Section 2), 200 registered users, 100
  transactions between two users with balance verification, 300 repeated
  balance updates.
- `tests/test_runner.c` / `tests/test_runner.h` — registers and runs
  every suite above via CUnit's basic interface, returning a non-zero
  exit code if any assertion fails (suitable for CI).
- `tests/test_common.c` / `tests/test_common.h` — shared test
  infrastructure: (1) a per-suite sandboxed working directory so tests
  never touch a developer's real `database/` folder or interfere with
  each other, and (2) an in-memory `stdin` redirection helper
  (`fmemopen`-based) used to drive the project's interactive,
  prompt-based functions (`registration_register`,
  `login_authenticate`, `account_change_credentials`,
  `account_deposit_funds`, `admin_run_panel`) from unit tests without
  changing their public interfaces.

**Result:** 89 tests, 918 assertions, 100% passing; the suite itself runs
cleanly under Valgrind with zero leaks and zero errors.

---

## 8. Integration testing

The smoke test (Section 6) and several unit tests exercise the full
Authentication → Account/Transaction → Integrity → Admin workflow
together against the real file-backed storage layer (not mocks),
confirming the modules work correctly end-to-end: e.g.
`test_admin_panel_freeze_unfreeze_clear_lockout` registers a user through
`registration_register()`, then drives the interactive admin panel
through `admin_run_panel()`, then reads the result back through
`storage_find_user()`; `test_stress_many_transactions_between_two_users`
combines registration, repeated transfers through
`transaction_transfer()`, and history retrieval through
`transaction_show_history()`.

---

## 9. Build system

`Makefile` updated to add `test`, `smoke`, `valgrind`, `cppcheck`, and
`misra` targets alongside the existing `all`, `clean`, `run`, and (the
previous, narrower) `test` target:

- `make` / `make all` — unchanged behavior, builds `bank` with the
  existing strict warning flags.
- `make clean` — now also removes the debug/analysis binaries and test
  binary produced by the new targets.
- `make test` — builds and runs the full CUnit suite (Section 7).
- `make smoke` — runs the smoke-test script (Section 6) against a fresh
  `database/`.
- `make valgrind` — builds a debug binary and runs it under Valgrind
  against `tests/valgrind_input.txt` (Section 5).
- `make cppcheck` — runs both CPPCheck passes (Section 4).
- `make misra` — recompiles with the full strict/`-fanalyzer` flag set
  used for the MISRA-oriented check (Section 1).

All seven targets were verified in a clean checkout as part of this pass.

---

## 10. Multithreading support (new)

**Goal:** make the existing storage/transaction/audit layer safe to
call from multiple threads, without rewriting it, removing any
feature, or changing any public function's signature or the on-disk
data formats. Every change below is additive (new locking wrapped
around the existing logic) or a narrow thread-safety fix
(`localtime` → `localtime_r`).

### 10.1 `storage.c` / `storage.h`

- Added a process-wide, re-entrant mutex (`pthread_mutex_t` with
  `PTHREAD_MUTEX_RECURSIVE`, lazily initialised via `pthread_once()`).
- Every existing public function's original body was renamed to a
  `static ..._impl()` function (unchanged line-for-line), and a thin
  public wrapper was added that takes the lock, calls `_impl()`, and
  releases the lock. Because the mutex is recursive, `_impl()`
  functions that call other public `storage_*` functions internally
  (e.g. `storage_add_user_impl()` calling `storage_find_user()`)
  continue to work unmodified.
- Exposed `storage_lock()` / `storage_unlock()` in `storage.h` so
  callers can group several `storage_*` calls into one atomic
  critical section (see 10.2).

### 10.2 Callers that need multi-call atomicity

The following functions read a record, decide something based on it,
and then write a record back — a classic check-then-act race if two
threads do this concurrently for the same account. Each one's
original body was renamed to `*_impl()` (unchanged) and a wrapper was
added that runs it inside `storage_lock()` / `storage_unlock()`:

- `transaction.c`: `transaction_transfer()` — validate, check sender
  balance, debit, credit, persist the transaction.
- `login.c`: `login_authenticate()` — read/clear a stale lockout,
  update the failed-attempt counter.
- `account.c`: `account_change_credentials()`, `account_deposit_funds()`.
- `admin.c`: `admin_ensure_default_account()` (scan for an existing
  admin, then create one), and the two static handlers
  `handle_set_frozen()` / `handle_clear_lockout()` used by the admin
  panel.

`registration.c` was left as-is: its pre-check + `storage_add_user()`
is still technically check-then-act, but `storage_add_user()` itself
re-checks for a duplicate username atomically under the lock before
appending, so the existing "reject duplicate usernames" guarantee
already holds under concurrency without further changes.

### 10.3 `audit.c`

Added a dedicated `pthread_mutex_t` guarding each log line's
`fopen()`/`fprintf()`/`fclose()` sequence, kept separate from the
storage mutex since `audit_log()` is called both from inside and
outside a held storage lock; this avoids coupling the two modules'
locking together while still preventing interleaved/corrupted log
lines under concurrent writers.

### 10.4 Thread-safety fix: `localtime()` → `localtime_r()`

`localtime()` returns a pointer to shared static storage and is not
thread-safe. `audit.c` and `transaction.c` (`make_timestamp()`) now
use `localtime_r()` with a local `struct tm` instead. This is a
behavior-preserving fix — the formatted output is identical — needed
only because these functions can now genuinely run on multiple
threads at once.

### 10.5 Build system

`Makefile`: added `-pthread` to `CFLAGS`/`LDFLAGS` and to the `test`,
`valgrind`, and `misra` targets' compiler invocations, so every build
(the app, the CUnit suite, the debug/Valgrind binary, and the strict
MISRA-profile check) links against `pthread`.

### 10.6 New test suite: `tests/test_concurrency.c`

A new CUnit suite (registered in `tests/test_runner.h`/`.c` alongside
the existing ten) that spins up 8 `pthread`s at a time and drives the
platform concurrently:

- **Concurrent registration** — 8 threads x 25 users each, all
  distinct accounts; asserts every one of the 200 records is present,
  well-formed, and independently findable afterwards.
- **Concurrent transfers** — 8 threads x 50 rounds each, all
  transferring between the same 5-account pool (so accounts are
  frequently contended from multiple threads at once); asserts no
  account ever goes negative (no overdraft race) and that the total
  balance across the pool is exactly conserved (no lost or duplicated
  funds), regardless of how many individual transfers succeeded or
  failed on insufficient balance.
- **Concurrent deposits** — 8 threads each repeatedly read-modify-
  write their *own* distinct account (mirroring
  `account_deposit_funds()`'s pattern directly via `storage_lock()` /
  `storage_find_user()` / `storage_update_user()` /
  `storage_unlock()`); asserts every one of each thread's increments
  is reflected, none lost to a race with another thread's unrelated
  account.
- **Concurrent audit logging** — 8 threads x 60 lines each; asserts
  every line in the resulting `audit.log` is well-formed (no
  interleaved/corrupted lines from two threads writing at once).

**Result:** 93 tests (89 previous + 4 new), 1031 assertions
(918 previous + 113 new), 0 failures — `make test` output:

```
Run Summary:    Type  Total    Ran Passed Failed Inactive
              suites     11     11    n/a      0        0
               tests     93     93     93      0        0
             asserts   1031   1031   1031      0      n/a
```

### 10.7 Verification

- **GCC, zero warnings:** `make all` and `make misra`
  (`-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wunused-parameter
  -fanalyzer`, now with `-pthread`) both still compile with zero
  warnings, including the new `storage_lock()`/`storage_unlock()`
  code and `tests/test_concurrency.c`.
- **CPPCheck:** `make cppcheck` — zero warnings, unchanged from
  before this pass.
- **ThreadSanitizer:** the full CUnit suite (all 11 suites) was
  additionally built with `-fsanitize=thread` and run; **zero data
  races reported**, confirming the locking added above actually
  eliminates the races the new concurrency tests are designed to
  catch (this is a stronger, more targeted check for a
  multithreading change than Valgrind's Memcheck, which does not
  detect data races).
- **AddressSanitizer + UBSan:** the same suite was also built with
  `-fsanitize=address,undefined` and run; **zero errors**, confirming
  no memory-safety or undefined-behavior regressions were introduced
  by the locking/wrapper changes (a Memcheck-equivalent check; the
  sandbox this pass ran in could not fetch the `libc6-dbg` package
  Valgrind itself requires, so ASan/UBSan were used as the
  equivalent verification instead).
- **Smoke test:** `make smoke` still passes end-to-end with a clean
  exit, unchanged from before this pass.
- No existing functionality, module interface, or on-disk data
  format was removed or changed; no existing test was modified.
