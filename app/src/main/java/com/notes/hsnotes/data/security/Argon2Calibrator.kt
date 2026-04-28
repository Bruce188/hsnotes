package com.notes.hsnotes.data.security

/**
 * First-run Argon2id memory tuner. Plan §10.2.
 *
 * The calibrator measures wall-time of an Argon2 derive at the configured
 * parameters and halves `m` (memoryKiB) until the measured time is at most
 * [targetMs] OR the [floorKiB] security minimum is reached. Iterations (`t`)
 * and parallelism (`p`) are NEVER changed — only memory.
 *
 * The probe is injected so JVM tests can drive the algorithm with deterministic
 * timings. Production wires [productionProbe] which runs an actual Argon2
 * derive timed via `System.currentTimeMillis()`.
 *
 * Algorithm:
 *  1. Measure derive time at [start] params.
 *  2. If ≤ `2 × targetMs`, return [start] unchanged (calibration unnecessary).
 *  3. Otherwise, while measured > [targetMs] AND `m > floorKiB`,
 *     halve `m` (floored at [floorKiB]) and re-measure.
 *  4. Return the final params (either ≤ target or pinned at the floor).
 *
 * Persistence is the caller's responsibility — see [ensureCalibrated] for the
 * production-wiring helper that idempotently runs the calibrator and writes
 * the result through a [CalibratedParamsStore].
 */
class Argon2Calibrator(
    private val probe: suspend (Argon2Params) -> Long,
    private val targetMs: Long = TARGET_MS_DEFAULT,
    private val floorKiB: Int = CryptoConfig.ARGON2_MEMORY_FLOOR_KIB,
) {

    /**
     * Drive the calibration loop and return tuned [Argon2Params].
     *
     * The returned params satisfy `memoryKiB >= floorKiB` and either:
     *  - the measured probe at the returned params is ≤ [targetMs], OR
     *  - the device is so slow that `memoryKiB == floorKiB` is reached
     *    even though the probe is still above target (the security
     *    minimum is never breached).
     */
    @Suppress("ForbiddenMethodCall")  // Review B10: calibration baseline.
    suspend fun calibrate(start: Argon2Params = Argon2Params.default()): Argon2Params {
        var p = start
        var elapsed = probe(p)
        // First-pass shortcut: if the configured params already complete at
        // ≤ 2× target, calibration is unnecessary. Plan-prose specifies a 2×
        // tolerance window so devices near the boundary do not thrash between
        // m and m/2 across reinstalls.
        if (elapsed <= 2 * targetMs) return p
        while (elapsed > targetMs && p.memoryKiB > floorKiB) {
            val nextM = maxOf(p.memoryKiB / 2, floorKiB)
            if (nextM == p.memoryKiB) break // already at floor
            p = p.copy(memoryKiB = nextM)
            elapsed = probe(p)
        }
        return p
    }

    companion object {
        /** Plan-mode § Verification step 7 — cold-start unlock target. */
        const val TARGET_MS_DEFAULT: Long = 1_000L

        /**
         * Production probe: runs a real Argon2id derive against the supplied
         * [kdf] with a throwaway passphrase + zero-salt and returns wall-time
         * in milliseconds. The derived material is wiped immediately.
         *
         * The probe is intentionally cheap to reason about — fixed plaintext,
         * fixed salt — because the only output is the timing measurement.
         * Argon2's runtime is data-independent so the dummy inputs do not
         * skew the calibration result.
         */
        fun productionProbe(kdf: Argon2Kdf): suspend (Argon2Params) -> Long = { params ->
            val pw = "calibration-probe".toCharArray()
            val salt = ByteArray(SALT_BYTES)
            val t0 = System.currentTimeMillis()
            val derived = kdf.derive(pw, salt, params)
            val elapsed = System.currentTimeMillis() - t0
            derived.wipe()
            elapsed
        }

        /**
         * Idempotently calibrate Argon2 memory and persist through [store].
         *
         * If [store] already holds a calibrated value, this is a no-op (the
         * stored params would have been used for KeyManager.setupNew so a
         * fresh calibration would invalidate the existing wrapped DEK).
         *
         * On first run, runs the calibrator using [probe] and writes the
         * tuned `memoryKiB` into [store]. Subsequent calls short-circuit
         * before [probe] is invoked.
         *
         * Production wires `probe = productionProbe(Argon2Kdf())`; JVM tests
         * pass a deterministic stub. The probe is the explicit injection
         * point because constructing a real [Argon2Kdf] on the JVM test
         * runtime can pull in native Argon2 libraries that aren't shipped
         * with the unit-test classpath.
         *
         * Plan §10.2 deviation: the plan specifies `SecurePrefs.ARGON2_CALIBRATED_M`
         * but SecurePrefs requires the DEK and is only populated post-unlock.
         * Calibrated params must be readable PRE-unlock (the AuthViewModel
         * factory needs them to construct KeyManager before any unlock can
         * happen), so they are routed to plaintext DataStore alongside the
         * other pre-unlock-readable fields (auth state, panic-PIN hash, etc.).
         * The memoryKiB integer is not sensitive — it reveals only the
         * device's calibrated cost, not any keying material.
         */
        suspend fun ensureCalibrated(
            store: CalibratedParamsStore,
            probe: suspend (Argon2Params) -> Long,
            targetMs: Long = TARGET_MS_DEFAULT,
        ) {
            if (store.calibratedArgon2MemoryKiB() != null) return
            val cal = Argon2Calibrator(probe = probe, targetMs = targetMs)
            @Suppress("ForbiddenMethodCall")  // Review B10: calibration baseline.
            val tuned = cal.calibrate(Argon2Params.default())
            store.setCalibratedArgon2MemoryKiB(tuned.memoryKiB)
        }

        /**
         * Convenience overload for production wiring — wraps an [Argon2Kdf]
         * with [productionProbe] and delegates to the probe-taking
         * [ensureCalibrated]. App.onCreate uses this form so the call site
         * does not have to assemble the probe lambda itself.
         */
        suspend fun ensureCalibrated(
            store: CalibratedParamsStore,
            kdf: Argon2Kdf = Argon2Kdf(),
            targetMs: Long = TARGET_MS_DEFAULT,
        ) {
            // Important: build the probe BEFORE checking the short-circuit
            // guard so the API surface mirrors the probe-taking variant.
            // Argon2Kdf construction itself is cheap (no native call until
            // derive is invoked), but if a future change to argon2kt makes
            // construction expensive we can re-order the guard back here.
            ensureCalibrated(store = store, probe = productionProbe(kdf), targetMs = targetMs)
        }

        private const val SALT_BYTES: Int = 16
    }
}
