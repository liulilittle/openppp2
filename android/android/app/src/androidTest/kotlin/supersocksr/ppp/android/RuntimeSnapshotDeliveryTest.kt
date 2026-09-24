package supersocksr.ppp.android

import android.content.Intent
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Covers the ordering gate every runtime snapshot passes through.
 *
 * Debug builds strip `android:process` from [PppVpnService]
 * (`app/src/debug/AndroidManifest.xml`), so the service shares this process and
 * its gate can be driven directly. That same override is why instrumentation
 * cannot reproduce the cross-process delivery defect itself -- the release
 * layout, where the service runs in `:vpn`, is enforced by the source checks in
 * `tests/tooling/test_runtime_ui_wiring.py` instead.
 */
@RunWith(AndroidJUnit4::class)
class RuntimeSnapshotDeliveryTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val serviceIntent = Intent(context, PppVpnService::class.java)

    private fun snapshot(generation: Long, monotonicMs: Long, phase: String): String {
        return "{\"schema_version\":1,\"generation\":$generation," +
            "\"monotonic_ms\":$monotonicMs,\"phase\":\"$phase\"}"
    }

    private fun mirrored(): String {
        return PppStateStore.getRuntimeSnapshotIfAlive(context) ?: ""
    }

    @Before
    fun startFreshService() {
        context.stopService(serviceIntent)
        waitUntil { PppVpnService.instance == null }
        assertNotNull(context.startService(serviceIntent))
        waitUntil { PppVpnService.instance != null }
        PppStateStore.clearRuntimeSnapshot(context)
        PppStateStore.setLinkState(context, 0)
    }

    @After
    fun stopService() {
        context.stopService(serviceIntent)
        PppStateStore.clearRuntimeSnapshot(context)
        PppStateStore.clearLinkState(context)
    }

    @Test
    fun outOfOrderSnapshotsCannotOverwriteNewerState() {
        val service = requireNotNull(PppVpnService.instance)

        service.onRuntimeSnapshot(snapshot(5, 100, "connected"))
        assertTrue(mirrored().contains("\"phase\":\"connected\""))

        // Native listeners run on whichever thread produced the transition, so
        // a late publish can arrive after a newer one.
        service.onRuntimeSnapshot(snapshot(5, 50, "idle"))
        assertTrue(mirrored().contains("\"phase\":\"connected\""))

        service.onRuntimeSnapshot(snapshot(5, 100, "failed"))
        assertTrue(mirrored().contains("\"phase\":\"connected\""))

        service.onRuntimeSnapshot(snapshot(4, 9000, "idle"))
        assertTrue(mirrored().contains("\"phase\":\"connected\""))

        // A newer generation always wins, even with a lower timestamp.
        service.onRuntimeSnapshot(snapshot(6, 1, "starting"))
        assertTrue(mirrored().contains("\"phase\":\"starting\""))
    }

    @Test
    fun malformedPushesLeaveTheMirrorUntouched() {
        val service = requireNotNull(PppVpnService.instance)

        service.onRuntimeSnapshot(snapshot(9, 10, "connected"))
        val good = mirrored()
        assertTrue(good.isNotEmpty())

        service.onRuntimeSnapshot("")
        service.onRuntimeSnapshot("not json at all")
        service.onRuntimeSnapshot("{\"schema_version\":1}")
        assertTrue(mirrored() == good)
    }

    @Test
    fun concurrentSnapshotsCannotLeaveAnOlderMirror() {
        val service = requireNotNull(PppVpnService.instance)
        val newer = snapshot(7, 200, "failed")
        val older = snapshot(7, 100, "connected")
        val start = java.util.concurrent.CountDownLatch(1)
        val done = java.util.concurrent.CountDownLatch(2)

        Thread {
            start.await()
            service.onRuntimeSnapshot(older)
            done.countDown()
        }.start()
        Thread {
            start.await()
            service.onRuntimeSnapshot(newer)
            done.countDown()
        }.start()

        start.countDown()
        assertTrue(done.await(5, java.util.concurrent.TimeUnit.SECONDS))

        // Gate + publish share one lock, so the mirror must end on the newer
        // payload even when both threads race through onRuntimeSnapshot.
        assertTrue(mirrored().contains("\"phase\":\"failed\""))
        assertTrue(mirrored().contains("\"monotonic_ms\":200"))
    }

    private fun waitUntil(condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + 5_000L
        while (!condition() && SystemClock.elapsedRealtime() < deadline) {
            SystemClock.sleep(25L)
        }
        assertTrue("condition timed out", condition())
    }
}
