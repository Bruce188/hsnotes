# Security Verification Runbook

Operator checklist for confirming the security retrofit is intact on a real
build. Run after every release, after merging any change that touches the
`data/security/`, `data/db/`, `data/backup/`, or `data/migration/` packages,
and any time you suspect tampering with the encrypted artifacts.

This is the human-driven half of plan § Verification. The unit / instrumented
tests are the automated half (Task 11.2 build gauntlet); they catch
regressions in the source. **This runbook catches regressions in the
artifacts on disk** — the ones a forensic analyst would attack.

---

## 0. Prerequisites

- A test device or emulator you are willing to wipe. **Do not run this on a
  device that holds real notes** — the wipe-path tests destroy them on
  purpose.
- `adb` on PATH, USB debugging enabled, and `adb root` available. On Pixel
  hardware this requires a userdebug build; on standard production hardware
  use an emulator (`emulator -no-snapshot -wipe-data`).
- `sqlite3` CLI installed locally (`apt install sqlite3` on the host).
- `xxd`, `strings`, `head`, `od` — standard coreutils.
- A scratch directory on the host for the pulled artifacts:
  ```bash
  WORK=$(mktemp -d) && cd "$WORK"
  ```

The application id is `com.notes.hsnotes`. The on-device data root is
`/data/data/com.notes.hsnotes/`.

---

## 1. Install + setup with the canonical fixture

```bash
./gradlew :app:installDebug
adb shell am start -n com.notes.hsnotes/.MainActivity
```

In the app:

1. The setup screen appears (it is the first screen on a fresh install).
2. Check the warning acknowledgement, wait the 5 s cooldown.
3. Enter passphrase **`correct horse battery staple`** in both fields.
4. Set a panic PIN: **`111111`** (six digits, distinct from passphrase).
5. Press **Continue**. The app transitions to the home screen.

Now seed test notes so the forensic exam has signal to find:

6. Add at least three notes with distinguishable content. Use these
   canonical fixtures so the `strings` greps below have predictable signal:
   - title `groceries`, body `milk, eggs, bread`, tag `personal`
   - title `rent reminder`, body `due on the 1st`, tag `bills`
   - title `book club`, body `Annihilation by Jeff VanderMeer`, no tag
7. Background the app (Home button) so all writes flush.

The remaining steps assume the app has been fully exited at least once after
seeding so the on-disk state is settled.

---

## 2. Forensic at-rest exam

Pull the entire app data root:

```bash
adb root
adb shell setenforce 0   # only if SELinux blocks the pull on your image
adb pull /data/data/com.notes.hsnotes/ ./pulled
cd pulled
```

### 2.1 Encrypted SQLCipher database

Path: `databases/notes.db`

```bash
sqlite3 databases/notes.db .tables
```

**Pass:** sqlite3 reports
```
Error: file is not a database
```
or `Error: file is encrypted or is not a database`.

**Fail:** sqlite3 prints any table names. That means SQLCipher is not
keying the DB — escalate immediately.

```bash
strings databases/notes.db | grep -iE 'groceries|rent|book club|Annihilation|personal|bills'
```

**Pass:** zero matches. Plaintext page content of the seeded notes
must not be findable by `strings`. (A handful of unrelated short ASCII
sequences are normal — the SQLCipher header itself contains none of the
greps above.)

**Fail:** any seeded value (`groceries`, `rent`, `Annihilation`, …) appears.
The DB is either plaintext or partially-encrypted — escalate.

### 2.2 Encrypted preferences (Tink AEAD)

Path: `files/datastore/securedata.preferences_pb`

```bash
od -An -c files/datastore/securedata.preferences_pb | head -5
xxd files/datastore/securedata.preferences_pb | head -10
```

**Pass:** the file contains base64-looking blobs (the Tink ciphertext
envelope) wrapped in a Protobuf preferences frame. No legible secret
strings visible.

```bash
strings files/datastore/securedata.preferences_pb | grep -iE 'passphrase|panic|groceries|rent|Annihilation'
```

**Pass:** zero matches.

The Tink keyset itself is at `files/sec/securedata_keyset.json`. It is
wrapped under an AEAD derived from the DEK, so the JSON envelope is
visible but the actual key material is opaque ciphertext:

```bash
cat files/sec/securedata_keyset.json | head -c 200
```

**Pass:** JSON shape (`{"encryptedKeyset":"...","keysetInfo":{...}}`) with
`encryptedKeyset` being base64 ciphertext. The wrapped key material is
unreadable without the DEK, which itself is unreadable without the
passphrase plus Keystore.

### 2.3 Plaintext settings (intentional, no secrets)

Path: `files/datastore/settings.preferences_pb`

This file is **plaintext on purpose**. It holds only fields that must be
readable before unlock can produce a DEK:

- auth state token (`fresh-install` / `setup-complete`)
- failed-attempt counter
- last-auth-success epoch (dead-man timer anchor)
- panic-PIN **hash** (Argon2id output, never the PIN itself)
- calibrated Argon2 memory cost in KiB (not sensitive)
- language preference

```bash
strings files/datastore/settings.preferences_pb
```

**Pass:** the only legible content is preference-key names (e.g.
`auth_state_v1`, `panic_pin_hash`, `argon2_calibrated_m_kib`,
`fail_count`, `last_auth_success_epoch`, `language`) and short scalar
values. No note titles or bodies, no PIN plaintext, no passphrase.

**Fail:** any of `groceries`, `rent`, `Annihilation`, the literal
passphrase `correct horse battery staple`, or the literal panic PIN
`111111` appears. Escalate.

---

## 3. Wipe-path verification (manual)

Each sub-step destroys data; redo Step 1 between them.

### 3.1 Five-fail wipe

1. Re-install + complete setup (Step 1).
2. Lock the app (background or wait the lock-timeout).
3. From the unlock screen, type a wrong passphrase 5 times in a row.
4. **Pass:** after the 5th failure, the app wipes itself and relaunches to
   the setup screen. Re-pull `/data/data/com.notes.hsnotes/` and
   confirm `databases/` is empty (or recreated empty), `files/datastore/`
   is empty, `files/sec/` is empty.

The threshold is `CryptoConfig.WIPE_FAIL_THRESHOLD` (= 5).
Attempts 3 and 4 surface a UI warning; attempt 5 triggers the wipe.

### 3.2 Panic-PIN wipe

1. Re-install + complete setup with panic PIN `111111` (Step 1).
2. Lock the app.
3. Enter `111111` at the unlock prompt (where the passphrase is normally
   entered).
4. **Pass:** the app appears to unlock briefly (decoy success — see plan
   § Panic) but immediately wipes and relaunches to setup. The panic PIN
   matches the stored hash, triggering the wipe path; the real
   passphrase does not.

### 3.3 Dead-man (14-day clock skew) wipe

1. Re-install + complete setup.
2. With the app fully closed, advance the device clock by 15 days:
   ```bash
   adb shell "su 0 date $(date -d '+15 days' +%m%d%H%M%Y.%S)"
   ```
   Or via Settings → System → Date & time → manual.
3. Cold-launch the app.
4. **Pass:** the app wipes on launch and the setup screen appears. The
   `LAST_AUTH_SUCCESS_EPOCH` check fires when `now - lastSuccess >
   DEAD_MAN_THRESHOLD` (= 14 days).

The clock-skew probe also rejects clocks that move *backward* by more
than the tolerance — same wipe path. Test that variant by setting the
clock to 30 days in the past; the wipe must fire.

After this test, restore the device clock before continuing.

---

## 4. Recents / screenshot blanking

1. Open the app to a sensitive screen (e.g. notes list, note edit).
2. Press the recents button.
3. **Pass:** the recents thumbnail shows a blank or system-icon tile. No
   note content is visible.
4. From the same screen, attempt a screenshot:
   ```bash
   adb shell screencap -p /sdcard/test.png && adb pull /sdcard/test.png
   ```
5. **Pass:** the captured image is blank / system-only / refused by the
   OS. The `FLAG_SECURE` window flag set in `MainActivity` (Task 5.4)
   plus the `AntiForensics.init` reflection-based recents-blanking
   (Task 1.4) cooperate to prevent screen capture.

---

## 5. Encrypted backup head check

1. From the running, unlocked app: Settings → Export backup.
2. Choose backup passphrase **`foo`** when prompted.
3. Save as e.g. `hsnotes-backup-YYYY-MM-DD.hsbk`.
4. Pull the file:
   ```bash
   adb pull /sdcard/Download/hsnotes-backup-*.hsbk ./
   ```
5. Inspect the head:
   ```bash
   head -c 100 hsnotes-backup-*.hsbk | xxd
   ```
6. **Pass:** the first four bytes are `HSBK` (the magic, ASCII), followed
   by a single version byte, then 16 bytes of salt, then nonce + AEAD
   ciphertext. **No JSON visible**. Beyond the fixed header the body is
   high-entropy random.

7. Round-trip: re-import with passphrase **`bar`** — must fail
   immediately with a `WrongBackupPassphrase` error (constant-time
   passphrase check + AEAD authentication tag rejection). Re-import with
   `foo` — must succeed and produce identical notes.

---

## 6. Performance smoke

Cold-start unlock — measured wall-clock from cold-launch icon-tap to
home-screen render — must fall in **0.5 s – 1.5 s** on the baseline
device (Pixel 4a-equivalent).

```bash
adb shell am force-stop com.notes.hsnotes
# Stopwatch the manual icon-tap → home-screen render path. Repeat 3×.
```

The Argon2 first-run calibrator (Task 10.2) tunes memory cost down from
the 256 MiB default toward a 1 s target on slower hardware. If unlock
exceeds 2 s on the baseline device:

1. Wipe and reinstall (forces a fresh calibration).
2. Re-measure. If still > 2 s, inspect
   `files/datastore/settings.preferences_pb` for `argon2_calibrated_m_kib`
   — it must be ≥ `CryptoConfig.ARGON2_MEMORY_FLOOR_KIB` (64 MiB) and ≤
   `CryptoConfig.ARGON2_MEMORY_KIB` (256 MiB).
3. If it has hit the 64 MiB floor and unlock is still > 2 s, the device
   is below the supported performance baseline. Escalate (do **not**
   lower the floor — it is the security minimum).

---

## 7. Pass criteria checklist

A release passes verification only when **every** box below is true:

- [ ] Step 2.1 — `sqlite3 notes.db .tables` errors out.
- [ ] Step 2.1 — `strings notes.db` finds no seeded values.
- [ ] Step 2.2 — `strings securedata.preferences_pb` finds no secrets.
- [ ] Step 2.3 — `settings.preferences_pb` contains only the documented
      pre-unlock fields.
- [ ] Step 3.1 — five wrong passphrase attempts wipe the app.
- [ ] Step 3.2 — panic PIN entry wipes the app.
- [ ] Step 3.3 — 15-day forward clock skew wipes the app on launch.
- [ ] Step 4 — recents thumbnail and `screencap` produce no note content.
- [ ] Step 5 — backup file starts with `HSBK` magic, body is opaque,
      wrong-passphrase import fails fast.
- [ ] Step 6 — cold-start unlock measured between 0.5 s and 1.5 s on the
      baseline device.

If any box is unchecked, the build does **not** ship. File an issue
referencing the failing step and the artifact (pulled tarball, logcat,
screencap) before shipping a fix.

---

## 8. Escalation contacts

Single-maintainer project. On any failure:

1. Open an issue tagged `security-regression` with the runbook step that
   failed plus the captured artifact.
2. Halt the release. The retrofit's threat model assumes a forensic
   analyst with full data-at-rest access — any failure here means the
   model is broken.
3. Bisect against the last green run of this runbook.

---

## Appendix A — Cross-reference to the source plan

| Runbook step | Plan § Verification step | Plan task |
|---|---|---|
| 1 | 1, 2 (setup) | 5.2, 5.3, 5.4 |
| 2.1 | 3 (forensic DB) | 3.1, 8.1 |
| 2.2 | 3 (forensic prefs) | 4.1 |
| 2.3 | 3 (forensic prefs) | 4.1 (routing rule) |
| 3.1 | 4 (5-fail wipe) | 7.1 |
| 3.2 | 4 (panic PIN) | 7.3 |
| 3.3 | 4 (dead-man) | 7.2 |
| 4 | 5 (recents/screenshot) | 1.4, 5.4 |
| 5 | 6 (backup) | 9.1 |
| 6 | 7 (performance) | 10.2 |

## Appendix B — Build gauntlet (Task 11.2)

The automated counterpart to this runbook. Run before every release,
gate the runbook on it being green:

```bash
./gradlew :app:lint :app:detektDebug :app:testDebugUnitTest \
          :app:assembleDebug :app:assembleRelease
# When a device/emulator is attached:
./gradlew :app:connectedDebugAndroidTest
```

All listed Gradle tasks must exit 0. `connectedDebugAndroidTest` is
optional only when no device is attached; the rest are non-negotiable.
