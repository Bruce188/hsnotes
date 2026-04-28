package com.notes.hsnotes.data.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Guards against accidental relaxation of security-critical constants.
 * If a constant changes, this test must change with it — and the change
 * must be reviewed.
 */
class CryptoConfigTest {

    @Test
    fun argon2_memory_param_is_at_least_64MB() {
        // 64 MiB = 65 536 KiB. Plan default is 256 MiB; floor is 64 MiB.
        assertTrue(
            "ARGON2_MEMORY_KIB must be >= 64MB; got ${CryptoConfig.ARGON2_MEMORY_KIB}",
            CryptoConfig.ARGON2_MEMORY_KIB >= 64 * 1024,
        )
        assertTrue(
            "ARGON2_MEMORY_FLOOR_KIB must be >= 64MB; got ${CryptoConfig.ARGON2_MEMORY_FLOOR_KIB}",
            CryptoConfig.ARGON2_MEMORY_FLOOR_KIB >= 64 * 1024,
        )
    }

    @Test
    fun argon2_iterations_at_least_3() {
        assertTrue(
            "ARGON2_ITERATIONS must be >= 3; got ${CryptoConfig.ARGON2_ITERATIONS}",
            CryptoConfig.ARGON2_ITERATIONS >= 3,
        )
    }

    @Test
    fun lockout_schedule_is_monotonic_non_decreasing() {
        val schedule = CryptoConfig.LOCKOUT_SCHEDULE_SECONDS
        assertTrue("Schedule must not be empty", schedule.isNotEmpty())
        for (i in 1 until schedule.size) {
            assertTrue(
                "Backoff regressed at index $i: ${schedule[i - 1]} -> ${schedule[i]}",
                schedule[i] >= schedule[i - 1],
            )
        }
    }

    @Test
    fun dead_man_window_is_14_days() {
        val expected = 14L * 24L * 60L * 60L * 1000L
        assertEquals(expected, CryptoConfig.DEAD_MAN_WINDOW_MS)
    }

    @Test
    fun wipe_threshold_is_5() {
        assertEquals(5, CryptoConfig.WIPE_FAIL_THRESHOLD)
    }

    @Test
    fun lock_timer_default_is_60s() {
        assertEquals(60_000L, CryptoConfig.LOCK_TIMER_DEFAULT_MS)
    }
}
