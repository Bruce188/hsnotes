package com.notes.hsnotes.data.security

/**
 * Central crypto + security tunables for the hsnotes security retrofit.
 *
 * Values are immutable defaults. The Argon2 calibrator (Task 10.2) may persist
 * adjusted memory in SecurePrefs but never below [ARGON2_MEMORY_FLOOR_KIB].
 *
 * Plan-mode reference: `~/.claude/plans/sounds-great-the-app-groovy-kahan.md`
 * § Architecture, § Wipe Ladder, § Anti-Forensics.
 */
object CryptoConfig {

    // --- Argon2id KDF parameters (RFC 9106) ---

    /** 256 MiB target memory. High enough to make off-device GPU brute force expensive. */
    const val ARGON2_MEMORY_KIB: Int = 256 * 1024

    /** Time-cost (passes). RFC 9106 Section 4 recommends t >= 1; we use 4 for cushion. */
    const val ARGON2_ITERATIONS: Int = 4

    /** Parallelism (lanes). 2 keeps unlock under target on modest devices. */
    const val ARGON2_PARALLELISM: Int = 2

    /** 64 MiB hard floor — calibrator may not drop below this even on slow hardware. */
    const val ARGON2_MEMORY_FLOOR_KIB: Int = 64 * 1024

    // --- Wipe ladder + lockout ---

    /** Lockout backoff per consecutive failed unlock attempt (1s, 2s, 5s, 30s, 5min). */
    val LOCKOUT_SCHEDULE_SECONDS: List<Int> = listOf(1, 2, 5, 30, 300)

    /** 14 days. Cryptographic erase fires if no successful unlock occurs within window. */
    const val DEAD_MAN_WINDOW_MS: Long = 14L * 24L * 60L * 60L * 1000L

    /** Number of consecutive failed unlock attempts that triggers a cryptographic erase. */
    const val WIPE_FAIL_THRESHOLD: Int = 5

    /** Default auto-lock timeout after backgrounding (60 seconds). User-configurable. */
    const val LOCK_TIMER_DEFAULT_MS: Long = 60_000L

    // --- Keystore + filesystem layout ---

    const val KEYSTORE_ALIAS_KEK: String = "hsnotes_kek_v1"
    const val KEYSTORE_ALIAS_ATTESTED_CLOCK: String = "hsnotes_attested_clock_v1"
    const val WRAPPED_DEK_FILENAME: String = "wrapped_dek.bin"
    const val KDF_SALT_FILENAME: String = "salt.bin"
    const val SEC_DIR_NAME: String = "sec"
}
