package com.notes.hsnotes.data.security

import com.notes.hsnotes.data.settings.AuthStateStore
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

/**
 * JVM unit-test coverage for [DeadManCheck]. Plan §7.2 Tests block.
 *
 * Every dependency (KeyManager, AuthStateStore, AttestedClock, Clock) is
 * replaced with an in-memory fake so the suite runs purely on JVM (no
 * Keystore, no DataStore IO).
 */
class DeadManCheckTest {

    @Test
    fun window_under_14d_does_not_trigger() = runTest {
        val now = 1_700_000_000_000L
        val km = FakeKeyManager(setupComplete = true)
        val auth = FakeAuthState(epoch = now - (CryptoConfig.DEAD_MAN_WINDOW_MS - 1_000L))
        val attested = FakeAttestedClock(stored = now - (CryptoConfig.DEAD_MAN_WINDOW_MS - 1_000L))
        val check = DeadManCheck(km, auth, attested, fixedClock(now))

        check.run()

        assertEquals(0, km.cryptoEraseCalls)
        assertEquals(now - (CryptoConfig.DEAD_MAN_WINDOW_MS - 1_000L), auth.epoch)
        assertEquals(now - (CryptoConfig.DEAD_MAN_WINDOW_MS - 1_000L), attested.stored)
    }

    @Test
    fun window_exactly_14d_triggers_wipe() = runTest {
        val now = 1_700_000_000_000L
        val km = FakeKeyManager(setupComplete = true)
        val auth = FakeAuthState(epoch = now - CryptoConfig.DEAD_MAN_WINDOW_MS)
        val attested = FakeAttestedClock(stored = now - CryptoConfig.DEAD_MAN_WINDOW_MS)
        val check = DeadManCheck(km, auth, attested, fixedClock(now))

        check.run()

        assertEquals(1, km.cryptoEraseCalls)
        assertNull(auth.epoch)
        assertNull(attested.stored)
    }

    @Test
    fun window_over_14d_triggers_wipe() = runTest {
        val now = 1_700_000_000_000L
        val km = FakeKeyManager(setupComplete = true)
        val auth = FakeAuthState(epoch = now - (CryptoConfig.DEAD_MAN_WINDOW_MS + 60_000L))
        val attested = FakeAttestedClock(stored = now - (CryptoConfig.DEAD_MAN_WINDOW_MS + 60_000L))
        val check = DeadManCheck(km, auth, attested, fixedClock(now))

        check.run()

        assertEquals(1, km.cryptoEraseCalls)
    }

    @Test
    fun attested_clock_rollback_still_triggers_via_max_of_two_sources() = runTest {
        // Attested file was wiped/tampered (read returns null) — but the
        // plaintext source still records a 15-day-old success. Max collapses
        // to the plaintext value, so the wipe still fires.
        val now = 1_700_000_000_000L
        val km = FakeKeyManager(setupComplete = true)
        val auth = FakeAuthState(epoch = now - (15L * 24L * 60L * 60L * 1000L))
        val attested = FakeAttestedClock(stored = null)
        val check = DeadManCheck(km, auth, attested, fixedClock(now))

        check.run()

        assertEquals(1, km.cryptoEraseCalls)
    }

    @Test
    fun secureprefs_clock_rollback_still_triggers_via_max_of_two_sources() = runTest {
        // Symmetric: plaintext source was cleared/tampered — but the attested
        // file still holds the 15-day-old success. Max grabs that, wipe fires.
        val now = 1_700_000_000_000L
        val km = FakeKeyManager(setupComplete = true)
        val auth = FakeAuthState(epoch = null)
        val attested = FakeAttestedClock(stored = now - (15L * 24L * 60L * 60L * 1000L))
        val check = DeadManCheck(km, auth, attested, fixedClock(now))

        check.run()

        assertEquals(1, km.cryptoEraseCalls)
    }

    @Test
    fun last_success_updated_on_unlock_callback() = runTest {
        val now = 1_700_000_000_000L
        val km = FakeKeyManager(setupComplete = true)
        val auth = FakeAuthState(epoch = null)
        val attested = FakeAttestedClock(stored = null)
        val check = DeadManCheck(km, auth, attested, fixedClock(now))

        check.recordSuccess()

        assertEquals(now, auth.epoch)
        assertEquals(now, attested.stored)
        assertEquals(0, km.cryptoEraseCalls)
    }

    @Test
    fun run_is_no_op_when_isSetupComplete_is_false() = runTest {
        val now = 1_700_000_000_000L
        val km = FakeKeyManager(setupComplete = false)
        // Even with timestamps both wildly stale, we must not wipe — there's
        // nothing to erase pre-setup, and running cryptoErase here would be a
        // confusing no-op that races with first-launch setup.
        val auth = FakeAuthState(epoch = now - (30L * 24L * 60L * 60L * 1000L))
        val attested = FakeAttestedClock(stored = now - (30L * 24L * 60L * 60L * 1000L))
        val check = DeadManCheck(km, auth, attested, fixedClock(now))

        check.run()

        assertEquals(0, km.cryptoEraseCalls)
        assertTrue("authState must not be touched", auth.epoch != null)
        assertTrue("attestedClock must not be touched", attested.stored != null)
    }

    private fun fixedClock(epochMs: Long): Clock =
        Clock.fixed(Instant.ofEpochMilli(epochMs), ZoneOffset.UTC)

    // -------------------------------------------------------------------------
    // fakes
    // -------------------------------------------------------------------------

    private class FakeKeyManager(
        private val setupComplete: Boolean,
    ) : KeyManagerApi {
        var cryptoEraseCalls: Int = 0
            private set

        override suspend fun isSetupComplete(): Boolean = setupComplete
        override suspend fun setupNew(passphrase: CharArray) = Unit
        override suspend fun unlock(passphrase: CharArray): Result<Dek> =
            Result.failure(WrongPassphrase())
        override suspend fun changePassphrase(oldPassphrase: CharArray, newPassphrase: CharArray) = Unit
        override suspend fun cryptoErase() {
            cryptoEraseCalls += 1
        }
    }

    private class FakeAuthState(
        var epoch: Long? = null,
    ) : AuthStateStore {
        override suspend fun currentFailCount(): Int = 0
        override suspend fun setFailCount(n: Int) = Unit
        override suspend fun setLastAuthSuccessEpoch(epochMs: Long?) {
            epoch = epochMs
        }
        override suspend fun lastAuthSuccessEpoch(): Long? = epoch
    }

    private class FakeAttestedClock(
        var stored: Long? = null,
    ) : AttestedClock {
        override suspend fun read(): Long? = stored
        override suspend fun write(epochMs: Long) {
            stored = epochMs
        }
        override suspend fun clear() {
            stored = null
        }
    }
}
