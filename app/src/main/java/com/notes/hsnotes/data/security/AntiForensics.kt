package com.notes.hsnotes.data.security

import android.app.Activity
import android.app.Application
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper

/**
 * One-shot anti-forensics init. Call exactly once from [Application.onCreate]
 * — see `App.kt`. Idempotent guard via [initialized].
 *
 * Plan-mode § Anti-Forensics. `FLAG_SECURE` is set on `MainActivity.onCreate`
 * (Task 5.4) because it is a per-Window flag.
 *
 * Hard rule: no `android.util.Log.*` calls — Task 10.1 detekt rule will fail
 * the build otherwise.
 */
object AntiForensics {

    @Volatile
    private var initialized: Boolean = false

    private const val CLIPBOARD_CLEAR_DELAY_MS = 30_000L

    fun init(application: Application) {
        if (initialized) return
        initialized = true

        // 1. Recents-screenshot suppression (API 33+). Activity-scoped API, so
        //    we register a lifecycle callback and apply on every Activity-created.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            application.registerActivityLifecycleCallbacks(
                object : Application.ActivityLifecycleCallbacks {
                    override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
                        runCatching { activity.setRecentsScreenshotEnabled(false) }
                    }
                    override fun onActivityStarted(activity: Activity) {}
                    override fun onActivityResumed(activity: Activity) {}
                    override fun onActivityPaused(activity: Activity) {}
                    override fun onActivityStopped(activity: Activity) {}
                    override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
                    override fun onActivityDestroyed(activity: Activity) {}
                },
            )
        }

        // 2. PR_SET_DUMPABLE = 0 to discourage core dumps + ptrace from non-root.
        //    Reflective: android.system.Os#prctl is annotated @SystemApi/@hide on
        //    older releases. Best-effort; failure is silently absorbed.
        runCatching {
            val osClass = Class.forName("android.system.Os")
            val prctl = osClass.getMethod(
                "prctl",
                Int::class.javaPrimitiveType,
                Long::class.javaPrimitiveType,
                Long::class.javaPrimitiveType,
                Long::class.javaPrimitiveType,
                Long::class.javaPrimitiveType,
            )
            // PR_SET_DUMPABLE = 4 from <sys/prctl.h>; value = 0 disables core dumps.
            prctl.invoke(null, 4, 0L, 0L, 0L, 0L)
        }
    }

    /**
     * Schedule a clipboard clear 30 seconds out. No-op if the clipboard is
     * empty at the time the scheduled work runs. Idempotent — re-scheduling
     * stacks but each execution merely overwrites the same primary clip.
     *
     * Currently no flow in hsnotes copies sensitive data to the
     * clipboard; this hook prevents future regression. Plan § Anti-Forensics.
     */
    fun clearClipboardSensitive(context: Context) {
        val appCtx = context.applicationContext
        Handler(Looper.getMainLooper()).postDelayed(
            {
                runCatching {
                    val cm = appCtx.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                        ?: return@runCatching
                    if (!cm.hasPrimaryClip()) return@runCatching
                    // Replace primary clip with an empty one (clearPrimaryClip is API 28+).
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        cm.clearPrimaryClip()
                    } else {
                        cm.setPrimaryClip(ClipData.newPlainText("", ""))
                    }
                }
            },
            CLIPBOARD_CLEAR_DELAY_MS,
        )
    }
}
