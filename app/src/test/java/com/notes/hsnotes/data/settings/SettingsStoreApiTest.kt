package com.notes.hsnotes.data.settings

import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import kotlin.coroutines.Continuation

/**
 * JVM unit-test coverage for [SettingsStore].
 *
 * The internal constructor accepting a `DataStore<Preferences>` lets us
 * point SettingsStore at a `PreferenceDataStoreFactory.create(produceFile =
 * tmp.preferences_pb)` instance — pure JVM, no Robolectric, no Android
 * Context required.
 */
class SettingsStoreApiTest {

    @get:Rule
    val tmp: TemporaryFolder = TemporaryFolder()

    private lateinit var store: SettingsStore
    private lateinit var dsFile: File

    @Before
    fun setUp() {
        dsFile = File(tmp.root, "settings_test.preferences_pb")
        val ds = PreferenceDataStoreFactory.create(produceFile = { dsFile })
        store = SettingsStore(ds)
    }

    @After
    fun tearDown() {
        dsFile.delete()
    }

    // -------------------------------------------------------------------------
    // 1. Public setters must keep their pinned signatures (suspend, first-arg).
    // -------------------------------------------------------------------------
    @Test
    fun setters_signature_compatibility_with_baseline() {
        // Suspend functions compile to (originalArgs..., Continuation<*>) on
        // the JVM. We assert each setter still has the documented first-arg
        // type and that it remains suspend (Continuation tail).
        val expected = mapOf(
            "setLanguage" to String::class.java,
            "setLockTimeoutMs" to java.lang.Long.TYPE,
        )
        val methods = SettingsStore::class.java.declaredMethods
            .filter { it.name in expected.keys }
            .associateBy { it.name }

        expected.forEach { (name, firstArgType) ->
            val m = methods[name] ?: error("Missing setter: $name")
            val params = m.parameterTypes
            assertTrue(
                "$name must have at least 2 JVM params (value + Continuation)",
                params.size >= 2,
            )
            assertEquals(
                "$name first param must be $firstArgType (got ${params[0]})",
                firstArgType,
                params[0],
            )
            assertEquals(
                "$name last param must be Continuation (suspend marker)",
                Continuation::class.java,
                params[params.size - 1],
            )
        }
    }

    // -------------------------------------------------------------------------
    // 2. Empty store yields the documented defaults.
    // -------------------------------------------------------------------------
    @Test
    fun flow_emits_default_settings_when_empty() = runBlocking {
        val s = store.flow.first()
        assertNull(s.language)
        assertNull(s.lastAuthSuccessEpoch)
        assertEquals(0, s.failCount)
        assertNull(s.panicPinHash)
        assertEquals(60_000L, s.lockTimeoutMs)
    }

    // -------------------------------------------------------------------------
    // 3. Round-trip: every setter persists; flow emits the new state.
    // -------------------------------------------------------------------------
    @Test
    fun flow_emits_persisted_settings_after_setters() = runBlocking {
        store.setLanguage("nl")
        store.setLastAuthSuccessEpoch(1_700_000_000_000L)
        store.setFailCount(3)
        store.setPanicPinHash(byteArrayOf(0x01, 0x02, 0x03, 0x04))
        store.setLockTimeoutMs(120_000L)

        val s = store.flow.first()
        assertEquals("nl", s.language)
        assertEquals(1_700_000_000_000L, s.lastAuthSuccessEpoch)
        assertEquals(3, s.failCount)
        assertTrue(s.panicPinHash!!.contentEquals(byteArrayOf(0x01, 0x02, 0x03, 0x04)))
        assertEquals(120_000L, s.lockTimeoutMs)

        // Nullable setters must round-trip null too.
        store.setLanguage(null)
        store.setLastAuthSuccessEpoch(null)
        store.setPanicPinHash(null)
        val cleared = store.flow.first()
        assertNull(cleared.language)
        assertNull(cleared.lastAuthSuccessEpoch)
        assertNull(cleared.panicPinHash)
    }
}
