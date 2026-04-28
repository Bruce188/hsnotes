package com.notes.hsnotes.data.security

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * JVM unit coverage for [Argon2Calibrator] + [CalibratedParamsStore]. Plan §10.2.
 *
 * The probe is faked with a deterministic timing function so the calibration
 * loop is exercised without invoking the Argon2 JNI (and without depending on
 * device performance characteristics).
 *
 * Persistence test name in the plan ("calibrated_params_persist_to_securePrefs")
 * predates the routing decision — calibrated `m` is plaintext-readable so the
 * AuthViewModel factory can construct KeyManager pre-unlock. The store
 * interface tested here ([CalibratedParamsStore]) is the same one
 * [com.notes.hsnotes.data.settings.SettingsStore] implements against the
 * plaintext DataStore. The test name is preserved verbatim per plan-mode
 * convention.
 */
class Argon2CalibrationTest {

    private val target = Argon2Calibrator.TARGET_MS_DEFAULT
    private val floor = CryptoConfig.ARGON2_MEMORY_FLOOR_KIB
    private val defaultM = CryptoConfig.ARGON2_MEMORY_KIB

    /** In-memory store double — matches the contract of SettingsStore's plaintext routing. */
    private class InMemStore : CalibratedParamsStore {
        var value: Int? = null
        override suspend fun calibratedArgon2MemoryKiB(): Int? = value
        override suspend fun setCalibratedArgon2MemoryKiB(memKiB: Int) { value = memKiB }
    }

    /**
     * Probe stub: returns wall-time as a function of `memoryKiB`. The map
     * holds the timings the test wants to surface; absent keys return
     * [defaultMs] so unmapped probes do not silently no-op.
     */
    private class ProbeStub(
        private val timings: Map<Int, Long>,
        private val defaultMs: Long = 0L,
    ) {
        var callCount = 0
        val seenMemoryKiB = mutableListOf<Int>()
        val asLambda: suspend (Argon2Params) -> Long = { params ->
            callCount += 1
            seenMemoryKiB += params.memoryKiB
            timings[params.memoryKiB] ?: defaultMs
        }
    }

    @Test
    fun calibration_targets_1s_within_tolerance_when_clock_in_range() = runTest {
        // Probe at 256 MiB returns 900 ms — inside the 2× target window.
        // Calibrator must short-circuit and return the start params unchanged.
        val probe = ProbeStub(mapOf(defaultM to 900L))
        val cal = Argon2Calibrator(probe = probe.asLambda, targetMs = target)

        val out = cal.calibrate(Argon2Params.default())

        assertEquals(defaultM, out.memoryKiB)
        assertEquals(CryptoConfig.ARGON2_ITERATIONS, out.iterations)
        assertEquals(CryptoConfig.ARGON2_PARALLELISM, out.parallelism)
        // Single probe — no halving loop entered.
        assertEquals(1, probe.callCount)
    }

    @Test
    fun calibration_lowers_m_when_actualMs_exceeds_2x_target() = runTest {
        // 256 MiB → 3000 ms (> 2× target so the loop fires)
        // 128 MiB →  800 ms (≤ target so the loop exits)
        val probe = ProbeStub(mapOf(
            defaultM to 3000L,
            defaultM / 2 to 800L,
        ))
        val cal = Argon2Calibrator(probe = probe.asLambda, targetMs = target)

        val out = cal.calibrate(Argon2Params.default())

        assertEquals(defaultM / 2, out.memoryKiB)
        // t and p are NEVER touched — only m.
        assertEquals(CryptoConfig.ARGON2_ITERATIONS, out.iterations)
        assertEquals(CryptoConfig.ARGON2_PARALLELISM, out.parallelism)
        // Probed once at 256 MiB, once at 128 MiB.
        assertEquals(listOf(defaultM, defaultM / 2), probe.seenMemoryKiB)
    }

    @Test
    fun calibration_never_drops_below_64MB_floor_even_on_slow_device() = runTest {
        // Pathologically slow device — every probe returns 5000 ms regardless
        // of m. The calibrator must halve down to the security floor (64 MiB)
        // and stop. Returning a sub-floor value would breach the security
        // minimum from CryptoConfig.
        val probe = ProbeStub(timings = emptyMap(), defaultMs = 5000L)
        val cal = Argon2Calibrator(probe = probe.asLambda, targetMs = target)

        val out = cal.calibrate(Argon2Params.default())

        assertEquals(floor, out.memoryKiB)
        // The loop must have visited 256 MiB → 128 MiB → 64 MiB and then
        // halted because the next halving step would breach the floor.
        // Any further probe at 64 MiB must not have re-entered the halving
        // branch (the loop guard `m > floorKiB` is exclusive of the floor).
        val seen = probe.seenMemoryKiB
        // Sequence: defaultM, defaultM/2, defaultM/4 == floor (assuming
        // defaultM == 256 MiB and floor == 64 MiB). Once we reach the floor
        // and re-probe, the next loop iteration must NOT halve below it.
        assertEquals(defaultM, seen.first())
        assertEquals(floor, seen.last())
        // Floor IS ARGON2_MEMORY_FLOOR_KIB — the security minimum.
        assertEquals(64 * 1024, out.memoryKiB)
    }

    @Test
    fun calibrated_params_persist_to_securePrefs() = runTest {
        // ensureCalibrated drives the calibrator end-to-end against an
        // injected probe and writes the tuned `m` through the store.
        val store = InMemStore()
        assertNull("precondition — store empty before calibration", store.calibratedArgon2MemoryKiB())

        val probe = ProbeStub(mapOf(
            defaultM to 4000L,
            defaultM / 2 to 600L,
        ))
        Argon2Calibrator.ensureCalibrated(
            store = store,
            probe = probe.asLambda,
            targetMs = target,
        )
        assertEquals("first run must persist tuned m", defaultM / 2, store.calibratedArgon2MemoryKiB())

        // Idempotency: a subsequent ensureCalibrated must NOT re-run the
        // calibrator because the wrapped DEK is keyed to the persisted m.
        // Re-running would change the params and invalidate unlock.
        val probe2 = ProbeStub(mapOf(defaultM to 100L))
        Argon2Calibrator.ensureCalibrated(
            store = store,
            probe = probe2.asLambda,
            targetMs = target,
        )
        assertEquals("ensureCalibrated must not overwrite existing calibration",
            defaultM / 2, store.calibratedArgon2MemoryKiB())
        assertEquals("probe must NOT have been invoked on the second call",
            0, probe2.callCount)
    }

    @Test
    fun kdf_derive_uses_calibrated_params_after_setup() = runTest {
        // After a calibration run persists tuned m, Argon2Params.calibratedOrDefault
        // must return params with the persisted m AND the security-fixed
        // iterations/parallelism. This is the link between the calibrator
        // and the KDF — KeyManager constructs Argon2Params via this helper
        // (in AuthViewModel.factory) so the wrapped DEK is keyed to the
        // calibrated cost.
        val store = InMemStore()

        // Default-path (no calibration yet) — must return default params.
        val before = Argon2Params.calibratedOrDefault(store)
        assertEquals(defaultM, before.memoryKiB)
        assertEquals(CryptoConfig.ARGON2_ITERATIONS, before.iterations)
        assertEquals(CryptoConfig.ARGON2_PARALLELISM, before.parallelism)

        // Persist a tuned value and re-read.
        store.setCalibratedArgon2MemoryKiB(defaultM / 2)
        val after = Argon2Params.calibratedOrDefault(store)
        assertEquals(defaultM / 2, after.memoryKiB)
        assertEquals(CryptoConfig.ARGON2_ITERATIONS, after.iterations)
        assertEquals(CryptoConfig.ARGON2_PARALLELISM, after.parallelism)
        assertNotEquals(before.memoryKiB, after.memoryKiB)
    }

}
