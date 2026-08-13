# Digital Banking & UPI Transaction Security Platform

A C99 command-line simulation of a digital banking / UPI payment
platform (in the spirit of Google Pay, PhonePe, Paytm, or SBI YONO),
built with a custom, dependency-free security stack:

- **SHA-256** for password/PIN hashing and transaction integrity hashing
- **AES-128** (ECB + PKCS#7 padding) for encrypting transaction payloads at rest

Both cryptographic primitives are implemented from scratch in this
repository (`src/sha256.c`, `src/aes.c`) per FIPS PUB 180-4 and FIPS
PUB 197 respectively — there is no OpenSSL or other crypto library
dependency.

## Project Structure

```
DigitalBankingUPI/
├── include/            Public headers for every module
│   ├── bank.h          Core User/Session structures, path constants
│   ├── auth.h          Registration & login interface
│   ├── account.h        Change credentials & deposit funds interface
│   ├── admin.h           Administrator panel interface
│   ├── sha256.h         SHA-256 interface
│   ├── aes.h            AES-128 interface
│   ├── storage.h        File-backed persistence interface
│   ├── transaction.h    Transaction struct + transfer/history interface
│   ├── integrity.h      Integrity verification interface
│   └── audit.h          Audit logging interface
├── src/
│   ├── main.c           Menu-driven entry point
│   ├── registration.c   DIGI-1, DIGI-3, DIGI-16: registration + PIN hashing
│   ├── login.c          DIGI-2, DIGI-20, DIGI-22: login/authentication + lockout
│   ├── account.c         Change password/PIN, deposit funds
│   ├── admin.c            Administrator panel: list/freeze/unfreeze/unlock users
│   ├── sha256.c          DIGI-18: SHA-256 implementation
│   ├── aes.c             DIGI-4, DIGI-5: AES-128 encrypt/decrypt engine
│   ├── storage.c         DIGI-8, DIGI-17, DIGI-21: secure storage
│   ├── transaction.c     DIGI-6, DIGI-7: UPI transfer + validation
│   ├── history.c         Transaction history display
│   ├── integrity.c       DIGI-9: integrity verification
│   └── audit.c           Audit log writer
├── test/
│   └── test_crypto.c    DIGI-10, DIGI-11: unit + integration tests
├── database/
│   ├── users.dat         Sample user records
│   ├── transactions.dat  Sample encrypted transactions
│   └── audit.log         Sample audit trail
├── Makefile
└── README.md
```

## Building

Requires `gcc` and a Linux (or any POSIX-ish) environment.

```sh
make        # builds ./bank
make run    # builds and runs ./bank
make test   # builds and runs the unit/integration test suite
make clean  # removes build artifacts
```

Compiles cleanly with `-std=c99 -Wall -Wextra -Wpedantic -Wshadow
-Wconversion -Wsign-conversion` and zero warnings.

## Running

```sh
./bank
```

```
=====================================
 Digital Banking & UPI Platform
=====================================
 1. Register
 2. Login
 3. Exit
=====================================
```

After logging in:

```
=====================================
 Welcome, <username>
=====================================
 1. Check Balance
 2. Transfer Money
 3. Transaction History
 4. Verify Transaction Integrity
 5. Logout
 6. Change Password/PIN
 7. Deposit Funds
=====================================
```

Logging in as an administrator (see "Administrator Panel" below)
routes to a separate menu instead of the dashboard above.

## Newly Added Features

### 1. Account lockout (brute-force protection)
- Each user record tracks `failedAttempts` and `lockedUntilEpoch`.
- After `MAX_FAILED_LOGIN_ATTEMPTS` (5, see `bank.h`) consecutive
  failed logins, the account is locked for `LOCKOUT_DURATION_SECONDS`
  (300s / 5 minutes by default).
- While locked, login is refused even with the correct password/PIN,
  and the remaining lockout time is shown.
- A successful login, or the lockout period expiring, automatically
  clears the counters. An administrator can also clear a lockout
  early from the Administrator Panel.

### 2. Change Password / PIN
- Dashboard option 6. Requires re-entering the *current* password and
  PIN before accepting a new one (defends against a walk-away
  session being used to silently change credentials).
- The new credentials go through the same validation rules as
  registration (password ≥ 6 chars, PIN is 4 or 6 digits) and are
  re-hashed with SHA-256 before being persisted.

### 3. Deposit Funds (cash deposit simulation)
- Dashboard option 7. Adds a positive amount directly to the
  logged-in user's own balance and updates `users.dat`.
- This is intentionally *not* written to `transactions.dat` as a
  `Transaction` record, since it has no counterparty (sender/receiver)
  the way a UPI transfer does — it is recorded in `audit.log` instead.

### 4. Administrator Panel
- The platform bootstraps a single default administrator account on
  first run if none exists yet: username `admin`, password
  `Admin@123`, PIN `000000` (see `DEFAULT_ADMIN_*` in `bank.h`). This
  should be changed immediately via "Change Password/PIN" after first
  login in any real deployment.
- Logging in as a user with `isAdmin = 1` routes to a separate
  Administrator Panel instead of the normal dashboard:
  - **List All Users** — username, role, frozen/active status, login
    lock status, balance, and failed-attempt count.
  - **Freeze / Unfreeze Account** — a frozen account cannot log in at
    all until unfrozen (independent of the brute-force lockout).
    Freezing an administrator account is refused.
  - **Clear Login Lockout** — manually resets `failedAttempts` and
    `lockedUntilEpoch` for a specified user.
- All admin actions are written to `audit.log`, attributed to the
  admin's username.

### Users database format change
`users.dat` now has four additional trailing fields:

```
username|passwordHashHex|upiID|balance|isAdmin|isFrozen|failedAttempts|lockedUntilEpoch
```

`storage.c` parses these defensively: if a line has only the original
four fields (an older-format record), the new fields default to `0`,
so pre-existing data files still load correctly.



### Password / PIN handling (DIGI-3)
- Passwords and PINs are never stored in plaintext.
- At registration, `password:pin` is combined into a single credential
  string and hashed with SHA-256; only the resulting 64-character hex
  digest (`passwordHash`) is persisted in `users.dat`.
- Login recomputes the same SHA-256 hash from the entered credentials
  and compares it against the stored digest.
- Plaintext password/PIN buffers are zeroed with `memset()` immediately
  after they are no longer needed.

### Transaction encryption (DIGI-4, DIGI-5)
- Each transfer's descriptive payload
  (`sender|receiver|amount|timestamp`) is encrypted with AES-128 in
  ECB mode with PKCS#7 padding before being written to
  `transactions.dat`, using a platform key defined in `transaction.c`.
- `history.c` decrypts this payload again when displaying a user's
  transaction history.
- Note: ECB mode is used here for simplicity of demonstration. A
  production system should use an authenticated mode (e.g. AES-GCM)
  with a unique IV/nonce per message, and a key sourced from an HSM/KMS
  rather than embedded in source code.

### Multithreading & thread safety
- The platform's storage layer (`storage.c`) is now safe to call from
  multiple threads at once. It is guarded internally by a
  process-wide, re-entrant (`PTHREAD_MUTEX_RECURSIVE`) mutex, so
  every `storage_*` function may be called concurrently from any
  number of threads without corrupting `users.dat` or
  `transactions.dat`.
- `storage_lock()` / `storage_unlock()` (declared in `storage.h`) are
  exposed so callers can group several `storage_*` calls into one
  atomic "read, decide, write" critical section. This matters
  because several operations are check-then-act by nature (read a
  balance, then write a new one) and would otherwise be able to lose
  an update, or allow an overdraft, if two threads interleaved
  between the read and the write. This locking is now applied around
  the full sequence in:
  - `transaction_transfer()` — check balances, debit sender, credit
    receiver, write the transaction record.
  - `login_authenticate()` — read/clear a stale lockout, apply the
    brute-force failed-attempt counter.
  - `account_change_credentials()` / `account_deposit_funds()` —
    read the current record, then write the updated one.
  - `admin_ensure_default_account()` and the admin panel's
    freeze/unfreeze/clear-lockout actions.
- `audit.c` has its own dedicated mutex around each log line's
  `fopen`/`fprintf`/`fclose`, so concurrent audit writes from
  different threads are never interleaved or lost.
- `localtime()` (not thread-safe: it returns a pointer to shared
  static storage) was replaced with `localtime_r()` everywhere a
  timestamp is generated (`audit.c`, `transaction.c`).
- None of this changes any public function's signature, the on-disk
  data formats, or single-threaded behavior; the locking is purely
  additive. The CLI (`main.c`) still runs single-threaded, as a
  banking CLI naturally would — the thread-safety work makes it
  possible to *build* multithreaded or multi-client front ends on
  top of this same storage/transaction/audit layer (e.g. a future
  network service handling several client connections on their own
  threads) without having to redesign the persistence layer.
- Building links with `-pthread` (see `Makefile`); `tests/test_concurrency.c`
  is a new CUnit suite that spins up several `pthread`s doing
  concurrent registrations, transfers, deposits, and audit-log writes
  and asserts no lost updates, no overdrafts, and no corrupted
  records/log lines. It has also been verified clean under both
  ThreadSanitizer (`-fsanitize=thread`, zero data races reported) and
  AddressSanitizer/UBSan (`-fsanitize=address,undefined`, zero
  errors) — see `CHANGES.md`.

### Integrity verification (DIGI-9)
- At transfer time, a separate SHA-256 hash is computed over the
  transaction's canonical plaintext fields and stored alongside the
  encrypted payload.
- "Verify Transaction Integrity" recomputes this hash from the stored
  fields and compares it to the persisted hash, reporting each
  transaction as **VERIFIED** or **TAMPERED**. This allows the
  platform to detect any direct modification of `transactions.dat`.

### Audit logging
- Every registration, login (success/failure), logout, transfer
  (success/failure), and integrity check is appended to
  `database/audit.log` with a timestamp, for forensic review.

### Input validation & secure coding (DIGI-13)
- All interactive input uses `fgets()` with bounded buffers — no
  `gets()`, `scanf("%s")`, or other unbounded input functions.
- Usernames must be 3-29 alphanumeric/underscore characters; passwords
  must be at least 6 characters; PINs must be exactly 4 or 6 digits.
- All file handles are checked for `NULL` after `fopen()` and are
  always closed.
- `storage_update_balance()` writes to a temporary file and uses
  `rename()` for an atomic-ish update, avoiding partial writes to
  `users.dat`.
- Transfers are validated end-to-end: sender and receiver must exist,
  must differ, and the amount must be positive and not exceed the
  sender's balance. If crediting the receiver fails after the sender
  has been debited, the platform attempts to roll back the debit.
- Every menu loop (main menu, dashboard, admin panel) detects a
  closed/exhausted input stream (EOF on stdin) and exits gracefully
  instead of spinning forever re-printing "Invalid choice" — this
  matters both for piped/scripted usage and as basic input-exhaustion
  robustness.

## Testing (DIGI-10, DIGI-11, DIGI-12)

`make test` builds `test_crypto` and runs:

- **SHA-256 known-answer tests** against the official NIST test
  vectors for the empty string, `"abc"`, and a multi-block message.
- **SHA-256 determinism/avalanche checks.**
- **AES-128 round-trip tests** (encrypt → decrypt → compare), including
  the empty-string edge case.
- **AES-128 FIPS-197 known-answer test** (Appendix B / C.1 single-block
  vector) to confirm the cipher matches the published standard, not
  just itself.
- **An integration test** exercising `storage_init()` →
  `storage_add_user()` → `transaction_transfer()` (success and every
  failure path) → `integrity_verify_user_transactions()`.

The application has also been run under Valgrind
(`valgrind --leak-check=full --show-leak-kinds=all`) across full
register/login/transfer/history/integrity/logout sessions with
**0 errors and 0 leaks**.

## Data File Formats

`users.dat` — one user per line, `|`-delimited:
```
username|passwordHashHex|upiID|balance
```

`transactions.dat` — one transaction per line, `|`-delimited:
```
sender|receiver|amount|timestamp|encryptedDataHex|integrityHashHex
```

`audit.log` — one event per line:
```
[YYYY-MM-DD HH:MM:SS] user=<username|SYSTEM> event=<description>
```

## Known Simplifications

This is a demonstration/learning platform, not a production banking
system. Notable simplifications versus a real deployment:

- AES-128-ECB is used instead of an authenticated mode like AES-GCM.
- The AES key is a hardcoded constant rather than being sourced from
  an HSM/KMS or per-user key material.
- The flat-file `|`-delimited store is now thread-safe for concurrent
  access from multiple threads *within one process* (see
  "Multithreading & thread safety" above), but it still has no
  cross-process locking, so it remains unsafe for concurrent access
  from multiple separate OS processes.
- There is no network layer; this is a single-process CLI simulation.
