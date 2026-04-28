# HS Notes

A small Android notes app, intentionally over-engineered around mobile data-at-rest security. The visible surface — a single notes table (title, body, optional tag, timestamps; list + edit screens) — is a vehicle. **The codebase exists to explore secure-by-design Android development end-to-end against a realistic offline-forensics adversary, and to put the specialist vocabulary into its proper place** rather than handwave it: **Argon2id** (RFC 9106) key derivation, **envelope encryption** with a **Keystore-bound KEK** (StrongBox-preferred), **SQLCipher** page-level encryption, **AEAD**-protected SharedPreferences via **Tink**, an **attested-clock dead-man** wipe trigger, a tiered **wipe ladder** (`LOCK` / `SOFT` / `CRYPTO_ERASE` / `NUCLEAR`), **anti-oracle** UI discipline, **panic PIN** with observable-cost equivalence, `FLAG_SECURE` recents/screenshot blanking, and a custom `HSBK` backup envelope with 4 KiB size-fingerprint padding.

- **Module:** `app/` (single Android module, Kotlin + Compose, minSdk 26, targetSdk 35)
- **Crypto stack:** Argon2id (RFC 9106) → Android Keystore (AES/GCM, hardware-backed when available) → SQLCipher 4.6.1 → Tink AEAD 1.13
- **Status:** v0.1.0, codebase ported from a private cashregister security-retrofit project. Connected-instrumented suite staged; on-device verification is on the backlog.

---

## Why this exists

This is a portfolio project built **explicitly to explore secure mobile design** — and to use the specialist vocabulary in the places it actually applies, rather than abstractly. Every term in the list below appears in the source with a real implementation behind it, not as a buzzword:

`KDF` · `salt` · `nonce` · `KEK` · `DEK` · `AEAD` · `AES/GCM` · `Argon2id` · `Keystore-bound key` · `StrongBox` · `envelope encryption` · `page-level encryption` · `cipher_memory_security` · `secure_delete` · `journal_mode = MEMORY` · `attested clock` · `dead-man check` · `crypto-erase` · `wipe ladder` · `anti-oracle` · `panic PIN` · `observable-cost equivalence` · `FLAG_SECURE` · `MediaProjection blanking` · `CharArray hygiene` · `zeroize` · `HSBK envelope` · `size-fingerprint padding`

The notes-app contract is deliberately tiny — "small enough that the security retrofit can dominate the codebase without becoming abstract." The interesting parts are:

- The structure of the **wipe ladder** and how each level's preconditions and postconditions are verified.
- The interplay between **Argon2 calibration**, the **dead-man check**, and the **wipe paths** — each depends on something that has to be true before any of the others run.
- The discipline around plaintext-by-design state vs encrypted state, and the documented rationale for every plaintext field.
- The **on-device verification protocol** in `documentation/security-verification.md`, meant to be run by hand with `adb` to demonstrate the threat-model claims hold against a real filesystem dump.

If anything looks wrong or under-specified, that is also part of the point — feedback welcome.

---

## Threat model

The adversary is assumed to have:

1. **Physical access** to a powered-off (cold) device after the user has set up the app and used it.
2. **Full filesystem read** via `adb pull /data/data/com.notes.hsnotes`, OEM service-mode dumps, or chip-off forensics.
3. **No knowledge of the user's passphrase or panic PIN** (the only secrets that exist outside the device).
4. **No access to a live, unlocked process** (no live RAM dump, no live debugger).

The adversary is assumed *not* to have:

- Knowledge of the user's passphrase (treated as a high-entropy secret, e.g. diceware).
- A working exploit against AES/GCM, Argon2id, or the Android Keystore HAL.

Under that model, every note byte at rest must be cryptographically inaccessible without the passphrase.

---

## Defense layers

```
┌─────────────────────────────────────────────────────────────┐
│ User passphrase  +  per-install random salt                 │
│        │                                                    │
│        ▼  Argon2id  (calibrated to ~1s on the actual device)│
│ DEK (32B)  ◄── never persisted in plaintext                 │
│        │                                                    │
│        ▼  AES/GCM under Keystore-bound KEK (hw if avail.)   │
│ wrappedDek.bin on disk                                      │
│        │                                                    │
│        ▼  SQLCipher page-level encryption                   │
│ notes.db   (every note, body, tag, timestamp)               │
└─────────────────────────────────────────────────────────────┘

Adjacent surfaces:
- Tink AEAD-encrypted SharedPreferences for sensitive UI state
- Plaintext DataStore for explicitly non-sensitive auth state
  (failCount, last-auth epoch, panic-PIN hash, calibrated Argon2 m)
- Encrypted backup envelope:  HSBK-magic + Argon2id + AES/GCM + 4 KiB padding
```

### 1. Passphrase → DEK derivation

- **Argon2id** with the parameters from RFC 9106, security-fixed `t = 4` and `p = 2`.
- **Memory cost is calibrated** on first launch by `Argon2Calibrator` — the prober halves `m` until a probe derive lands inside the target window (~1 s) on the actual device, with a hard floor of 64 MiB so a slow eMMC device cannot accidentally drop below the RFC 9106 lower bound for a low-threat scenario.
- The calibrated `m` is persisted so cold-boot unlock latency is stable across launches.
- The same calibrated parameters are used for the panic-PIN hash and for the encrypted-backup KDF, so register-time and verify-time hashes always agree.

### 2. DEK wrapping (envelope encryption)

- The Argon2 output (32 B) is the **DEK**.
- The DEK is wrapped under a **Keystore-bound KEK** with AES/GCM. Hardware-backed StrongBox is requested first; fall back to software-backed Keystore if unavailable. `setRandomizedEncryptionRequired(false)` is opted out so the envelope can carry a caller-supplied 12-byte SecureRandom IV, giving a uniform `[12B nonce][ct][tag]` layout for both software and hardware keys.
- Only the wrapped form (`wrappedDek.bin`) is on disk. The raw DEK never leaves a method scope without a `wipe()` call in a `finally`.

### 3. Database-at-rest

- **SQLCipher 4.6.1** under Room. The DEK is the page key.
- Pragmas set at every connection open via `SQLiteDatabaseHook.postKey`:
  - `cipher_memory_security = ON` — zero page buffers in mlocked memory on unmap (blocks the "swap-out plaintext" forensic path).
  - `secure_delete = ON` — zero pages before reuse so deleted notes leave no recoverable residue inside the encrypted blob.
  - `journal_mode = MEMORY` — no on-disk journal; rollback state lives in RAM only.
- The journal-mode + secure-delete pair is database-scoped, so reader connections in the SQLCipher pool see a `SQLiteDatabaseLockedException` when the primary holds the init write lock — the hook swallows that specific exception because the primary's earlier `SET` is already in effect for the whole DB.
- Schema migrations are explicit; `fallbackToDestructiveMigration` is intentionally absent — silently losing encrypted user notes on schema mismatch defeats the entire point of the retrofit.

### 4. SharedPreferences (Tink)

- Sensitive UI state (lock timeout, etc.) routes through a `SecurePrefs` adapter wrapping a Tink AES/GCM AEAD keyset.
- The Tink keyset is itself encrypted under the same Keystore-bound KEK, so unlock-time DEK is *not* required to read those prefs — but the KEK gate is.
- Auth-pre-unlock state (`failCount`, `lastAuthSuccessEpoch`, `panicPinHash`, calibrated `m`) is held in plaintext DataStore by design: the wipe ladder, dead-man check, and panic-PIN compare must all run *before* the DEK has been derived.

### 5. Wipe ladder

Four wipe levels are defined; each is invoked from a different threat scenario:

| Level | Trigger | Effect |
|-------|---------|--------|
| `LOCK` | Background timeout | UI returns to lock; in-memory DEK + DB connection torn down. No disk change. |
| `SOFT` | User panic gesture from inside the app | Crypto-erase + UI lock. |
| `CRYPTO_ERASE` | Panic-PIN match, 5 wrong-passphrase attempts, or dead-man timeout | Keystore alias deleted **first**, then `wrappedDek.bin` and `salt` are securely overwritten and unlinked. Order matters: a partial wipe leaves the wrap files cryptographically useless rather than orphaning a Keystore alias. |
| `NUCLEAR` | Manual "wipe everything" from settings | `CRYPTO_ERASE` + delete `notes.db`/WAL/SHM, DataStore dir, `secure_prefs.{bin,json}`, `sec/`, `exports/`, `cacheDir`, `codeCacheDir`, `externalFilesDir`. |

The dead-man check fires before any UI/DB/DEK init in `App.onCreate`, fail-closed: if the setup-complete flag is set but both attested-clock sources are null (tampered), the wipe runs.

The attested clock is an HMAC-SHA256 timestamp under a Keystore alias (`hsnotes_attested_clock_v1`), written atomically on every successful unlock and on `setupNew`. If wall-clock time is ever moved forward more than 14 days past the last attested write, the wipe runs.

### 6. Panic PIN

- A second secret (≥ 6 digits, must differ from the passphrase) registered at setup.
- Stored as `Argon2id(pin, salt)` next to a 16-byte salt in plaintext DataStore (see point 4 — pre-unlock readability is mandatory).
- At unlock, the panic-PIN compare runs **before** the real Argon2 derive on the entered passphrase, so the wall-clock cost of an entered string is independent of whether it is the panic PIN, the real passphrase, or a wrong guess.
- A panic-PIN match shows a 200 ms fake-Unlocked window before crypto-erase fires — a real adversary watching the screen sees no observable difference between a successful unlock and a successful panic.

### 7. Encrypted backup format

- Wire format: `[HSBK:4][version:1][salt:16][nonce:12][ciphertext+tag]`.
- AAD covers `magic + version + salt`.
- Plaintext layout inside the AEAD: `[payloadLen:UInt32 BE][JSON][random padding]` so the ciphertext file size always aligns to the next 4 KiB multiple — the on-disk size cannot be used to fingerprint the user's note count.
- A single failure type (`WrongBackupPassphrase`) collapses *wrong-passphrase / corrupt-header / truncated-file* into one indistinguishable error — no decryption oracle.
- The backup KDF uses a deliberately lighter parameter set (64 MiB / t=3 / p=1) so re-keying a backup on a slower device is workable; the unlock-time KDF stays at the calibrated `m` / t=4 / p=2.
- A `BackupPassphraseGuard` enforces "backup passphrase MUST differ from unlock passphrase" at the ViewModel layer.

### 8. Recents + screenshot blanking

- `FLAG_SECURE` is set on the auth Activity window before `setContent`, so the first frame is opaque to the recents thumbnailer and to `MediaProjection`-style screen-capture services.
- An `AntiForensics` one-shot init runs in `App.onCreate` to set the application's recents-API-relevant flags as soon as the lifecycle exposes them.

### 9. UI-side passphrase hygiene

- All passphrase input flows are `CharArray`-backed, not `String`, so the GC cannot leave a copy alive in the string-intern pool.
- Buffers are wiped on every keystroke and again on `DisposableEffect.onDispose` so that screen rotations and back-stack pops do not leak.
- Compose's stock `OutlinedTextField` bridges through an internal `String`; the residual exposure is documented in each screen's header. A custom `TextField` would close that gap and is on the backlog.

---

## Notable engineering decisions (and why)

- **Hook scope is intentionally minimal.** The SQLCipher hook is the smallest piece of code that runs with the page key in scope. Its responsibilities are limited to setting the three pragmas above; everything else (seeding, migration, etc.) is in `RoomDatabase.Callback` or in the migration class.
- **`fallbackToDestructiveMigration` is forbidden.** A schema mismatch is *always* a bug; silently throwing away encrypted user notes on schema mismatch breaks the whole trust contract. Explicit `Migration` objects only.
- **Plaintext DataStore is a deliberate choice, not a leak.** Auth-state (`failCount`, `lastAuthSuccessEpoch`, `panicPinHash`, calibrated `m`) is the only data the wipe ladder, dead-man check, and panic-PIN compare are allowed to read *before* a successful unlock — they cannot depend on a SecurePrefs that needs the DEK. The non-secret nature of each field is documented at the source.
- **Detekt's `ForbiddenMethodCall`** is wired into `:app:check` to ban `android.util.Log.{v,d,i,w,e,wtf}` from production sources. Tests can use Log freely. The baseline starts empty so future regressions surface immediately.
- **Anti-oracle discipline.** All authentication failures collapse to one generic banner. No "wrong passphrase" vs "no setup" vs "Keystore corruption" distinction is surfaced to the UI — an attacker observing the screen cannot probe state.
- **Cold-start blocking is one synchronous call.** Argon2 calibration, DataStore reads, and locale apply are dispatched onto `applicationScope.async`; the only mandatory main-thread block is the dead-man check (it has to fail closed before any other code runs).

---

## Layout

```
app/
├── build.gradle.kts
└── src/
    ├── main/java/com/notes/hsnotes/
    │   ├── App.kt                       # one-shot init: dead-man, anti-forensics, calibrator, lifecycle lock
    │   ├── data/
    │   │   ├── backup/                  # HSBK envelope codec, BackupPassphraseGuard
    │   │   ├── db/                      # AppDatabase, NoteDao, NoteEntity
    │   │   ├── migration/               # Plaintext-to-cipher first-run upgrade
    │   │   ├── repo/                    # NotesRepository (timestamp policy + backup bridge)
    │   │   ├── security/                # KeyManager, Argon2Kdf, Argon2Calibrator,
    │   │   │                            #   AttestedClock, PanicPin, WipeManager,
    │   │   │                            #   SecurePrefs, Zeroize
    │   │   └── settings/                # SettingsStore, AuthStateStore, PanicPinStore
    │   └── ui/
    │       ├── auth/                    # AuthViewModel, LockState, SetupScreen, AuthGateScreen
    │       ├── migration/               # MigrationWizardScreen
    │       └── screens/                 # list/, edit/, settings/
    ├── test/                            # JVM unit tests
    └── androidTest/                     # connected-instrumented (staged)

documentation/
└── security-verification.md             # forensic black-box runbook
```

---

## Build

```bash
./gradlew :app:assembleDebug
./gradlew :app:assembleRelease
```

## Verify

```bash
./gradlew :app:lint
./gradlew :app:detektDebug          # banned-method check (Log.*) + zero baseline
./gradlew :app:testDebugUnitTest    # JVM unit tests
./gradlew :app:check                # lint + detekt + unit tests
./gradlew :app:connectedDebugAndroidTest   # instrumented suite, requires a device
```

The `documentation/security-verification.md` runbook contains an end-to-end forensic black-box check: install, set up, write notes, `adb pull`, attempt to open `notes.db` with `sqlite3`, run `strings` over the DataStore + secure prefs blobs, exercise each of the four wipe paths, and verify the encrypted-backup magic.
