package supersocksr.ppp.android

import android.Manifest
import android.app.Activity
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.net.VpnService
import android.os.Build
import android.util.Base64
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.io.ByteArrayOutputStream
import org.json.JSONObject

class MainActivity : FlutterActivity() {
    companion object {
        private const val METHOD_CHANNEL = "supersocksr.ppp/vpn"
        private const val VPN_PERMISSION_REQUEST = 1001
        private const val NOTIFICATION_PERMISSION_REQUEST = 1002
    }

    private var pendingConfig: String? = null
    private var pendingVpnOptions: String? = null
    private var methodResult: MethodChannel.Result? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        requestNotificationPermissionIfNeeded()

        // Method Channel
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, METHOD_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "connect" -> {
                        val args = call.arguments as? Map<*, *>
                        val config = args?.get("configJson") as? String
                        if (config == null) {
                            result.error("INVALID_ARG", "Config JSON is required", null)
                            return@setMethodCallHandler
                        }
                        val options = args["vpnOptions"] as? Map<*, *>
                        handleConnect(config, JSONObject(options ?: emptyMap<Any, Any>()).toString(), result)
                    }
                    "disconnect" -> {
                        handleDisconnect(result)
                    }
                    "readLog" -> {
                        result.success(PppLog.read(this))
                    }
                    "getLogPath" -> {
                        result.success(PppLog.path(this))
                    }
                    "clearLog" -> {
                        PppLog.clear(this)
                        result.success(true)
                    }
                    "getRuntimeSnapshot" -> {
                        // Mirrored by PppVpnService from the `:vpn` process;
                        // null while that process is not alive.
                        result.success(PppStateStore.getRuntimeSnapshotIfAlive(this))
                    }
                    "getLastError" -> {
                        result.success(PppStateStore.getLastError(this))
                    }
                    "getVpnHeartbeatAgeMs" -> {
                        // Returns milliseconds since :vpn last wrote the link
                        // state file. UI uses this as a liveness signal --
                        // even when log/state markers haven't progressed
                        // (e.g. native engine is busy parsing GeoIP.dat for
                        // 60s), the link-state poller keeps writing once a
                        // second so the file mtime is fresh. -1 means file
                        // doesn't exist yet (no session has started).
                        result.success(PppStateStore.heartbeatAgeMs(this))
                    }
                    "getInstalledApps" -> {
                        val includeSystem = (call.argument<Boolean>("includeSystem")) ?: false
                        result.success(loadInstalledApps(includeSystem))
                    }
                    "getAppIcon" -> {
                        val pkg = call.argument<String>("package")
                        if (pkg.isNullOrEmpty()) {
                            result.success(null)
                        } else {
                            result.success(loadAppIconBase64(pkg))
                        }
                    }
                    "getTelemetryIdentity" -> {
                        TelemetryIdentity.installIfNeeded(this)
                        result.success(TelemetryIdentity.identityPayload(this))
                    }
                    "requestPermission" -> {
                        requestVpnPermission(result)
                    }
                    else -> result.notImplemented()
                }
            }
    }

    private fun handleConnect(config: String, vpnOptions: String, result: MethodChannel.Result) {
        try {
            PppLog.write(this, "connect requested")
            if (!PppStateStore.isVpnAlive(this)) {
                PppStateStore.set(this, 0)
                PppStateStore.clearLinkState(this)
            }
            PppStateStore.set(this, 1)
            val vpnIntent = VpnService.prepare(this)
            if (vpnIntent != null) {
                // Need to request VPN permission first
                pendingConfig = config
                pendingVpnOptions = vpnOptions
                methodResult = result
                startActivityForResult(vpnIntent, VPN_PERMISSION_REQUEST)
            } else {
                // Permission already granted, start VPN
                startVpnService(config, vpnOptions)
                result.success(true)
            }
        } catch (e: Throwable) {
            PppStateStore.set(this, 0)
            PppLog.write(this, "handleConnect failed", e)
            result.error("CONNECT_FAILED", e.message ?: e.javaClass.name, PppLog.read(this))
        }
    }

    private fun handleDisconnect(result: MethodChannel.Result) {
        PppStateStore.set(this, 0)
        val intent = Intent(this, PppVpnService::class.java).apply {
            action = PppVpnService.ACTION_DISCONNECT
        }
        try {
            startService(intent)
            result.success(true)
        } catch (e: Throwable) {
            // PppVpnService statics live in `:vpn`; this process always reads
            // its own zeroed copy, so record the disconnected state directly.
            PppStateStore.set(this, 0)
            PppLog.write(this, "disconnect failed", e)
            result.error("DISCONNECT_FAILED", e.message ?: e.javaClass.name, PppLog.read(this))
        }
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(
                arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                NOTIFICATION_PERMISSION_REQUEST
            )
        }
    }

    private fun requestVpnPermission(result: MethodChannel.Result) {
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            methodResult = result
            startActivityForResult(vpnIntent, VPN_PERMISSION_REQUEST)
        } else {
            result.success(true) // Already granted
        }
    }

    private fun startVpnService(config: String, vpnOptions: String) {
        val intent = Intent(this, PppVpnService::class.java).apply {
            action = PppVpnService.ACTION_CONNECT
            putExtra(PppVpnService.EXTRA_CONFIG, config)
            putExtra(PppVpnService.EXTRA_VPN_OPTIONS, vpnOptions)
        }
        try {
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                startForegroundService(intent)
            } else {
                startService(intent)
            }
        } catch (e: Throwable) {
            PppLog.write(this, "startVpnService failed", e)
            throw e
        }
    }

    /**
     * Returns metadata for installed apps, used to drive the per-app proxy
     * picker. Each entry is { package, label, system }. System apps are
     * filtered out by default; pass includeSystem=true to also return them.
     * Icons are NOT included here -- the UI loads them lazily via
     * [loadAppIconBase64] to avoid blowing up the Method Channel payload.
     */
    private fun loadInstalledApps(includeSystem: Boolean): List<Map<String, Any?>> {
        val pm = packageManager
        val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
        val out = ArrayList<Map<String, Any?>>(apps.size)
        for (info in apps) {
            // Skip our own VPN app -- self-proxying creates a loop.
            if (info.packageName == this.packageName) continue
            val isSystem = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            if (isSystem && !includeSystem) continue
            // Drop apps that have no INTERNET permission -- they can never
            // generate traffic so listing them only adds noise.
            val hasInternet = pm.checkPermission(
                Manifest.permission.INTERNET,
                info.packageName
            ) == PackageManager.PERMISSION_GRANTED
            if (!hasInternet) continue
            val label = try {
                pm.getApplicationLabel(info).toString()
            } catch (_: Throwable) {
                info.packageName
            }
            out.add(
                mapOf(
                    "package" to info.packageName,
                    "label" to label,
                    "system" to isSystem,
                )
            )
        }
        // Stable ordering by label, case-insensitive.
        out.sortWith(compareBy(String.CASE_INSENSITIVE_ORDER) { (it["label"] as? String) ?: "" })
        return out
    }

    /**
     * Renders an app icon to a 96x96 PNG and returns its base64 string so
     * Flutter can decode it into MemoryImage. Returns null when the icon
     * cannot be resolved.
     */
    private fun loadAppIconBase64(pkg: String): String? {
        return try {
            val icon: Drawable = packageManager.getApplicationIcon(pkg)
            val bmp = drawableToBitmap(icon, 96, 96)
            val out = ByteArrayOutputStream()
            bmp.compress(Bitmap.CompressFormat.PNG, 100, out)
            Base64.encodeToString(out.toByteArray(), Base64.NO_WRAP)
        } catch (_: Throwable) {
            null
        }
    }

    private fun drawableToBitmap(drawable: Drawable, w: Int, h: Int): Bitmap {
        if (drawable is BitmapDrawable && drawable.bitmap != null) {
            return Bitmap.createScaledBitmap(drawable.bitmap, w, h, true)
        }
        val bitmap = Bitmap.createBitmap(
            if (drawable.intrinsicWidth > 0) drawable.intrinsicWidth else w,
            if (drawable.intrinsicHeight > 0) drawable.intrinsicHeight else h,
            Bitmap.Config.ARGB_8888,
        )
        val canvas = Canvas(bitmap)
        drawable.setBounds(0, 0, canvas.width, canvas.height)
        drawable.draw(canvas)
        return Bitmap.createScaledBitmap(bitmap, w, h, true)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_PERMISSION_REQUEST) {
            if (resultCode == Activity.RESULT_OK) {
                val config = pendingConfig
                if (config != null) {
                    try {
                        startVpnService(config, pendingVpnOptions ?: "{}")
                        methodResult?.success(true)
                    } catch (e: Throwable) {
                        PppLog.write(this, "startVpnService after permission failed", e)
                        methodResult?.error("CONNECT_FAILED", e.message ?: e.javaClass.name, PppLog.read(this))
                    }
                } else {
                    methodResult?.success(true) // Permission granted
                }
            } else {
                methodResult?.error("PERMISSION_DENIED", "VPN permission denied by user", null)
            }
            pendingConfig = null
            pendingVpnOptions = null
            methodResult = null
        }
    }
}
