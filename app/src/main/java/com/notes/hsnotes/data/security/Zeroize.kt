package com.notes.hsnotes.data.security

/**
 * Manual zeroization helpers for sensitive in-memory material.
 *
 * `String` is immutable on the JVM; once a passphrase enters a `String` it is
 * impossible to wipe before GC. Always use `CharArray` (UI layer) or `ByteArray`
 * (crypto layer) and call [wipe] in a `finally` (or via [useThenWipe]).
 *
 * No Android imports — pure JVM. Plan-mode § Anti-Forensics.
 */

/** Overwrite every byte with zero. Idempotent; safe on empty arrays. */
fun ByteArray.wipe() {
    for (i in indices) this[i] = 0
}

/** Overwrite every char with the space character. Idempotent; safe on empty arrays. */
fun CharArray.wipe() {
    for (i in indices) this[i] = ' '
}

/**
 * Run [block] with the receiver, then unconditionally call [wipe] — even if
 * [block] throws. Wipe runs in a `finally`, so the receiver is always
 * scrubbed before the call site regains control.
 *
 * Generic so it works with `ByteArray`, `CharArray`, or any sensitive holder
 * that exposes its own wipe operation:
 *
 * ```
 * val bytes = passphrase.toByteArray(Charsets.UTF_8)
 * val key = bytes.useThenWipe(wipe = { wipe() }) { kdf.derive(it, salt) }
 * // `bytes` is now zeroed regardless of derive() outcome.
 * ```
 */
inline fun <T : Any, R> T.useThenWipe(wipe: T.() -> Unit, block: (T) -> R): R {
    try {
        return block(this)
    } finally {
        this.wipe()
    }
}
