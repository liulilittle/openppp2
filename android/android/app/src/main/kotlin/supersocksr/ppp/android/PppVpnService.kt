package supersocksr.ppp.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.os.SystemClock
import android.system.OsConstants
import android.util.Log
import org.json.JSONObject
import supersocksr.ppp.android.c.libopenppp2

class PppVpnService : VpnService() {
    companion object {
        private const val TAG = "PppVpnService"
        private const val CHANNEL_ID = "openppp2_vpn_channel"
        private const val NOTIFICATION_ID = 1

        const val ACTION_CONNECT = "supersocksr.ppp.android.ACTION_CONNECT"
        const val ACTION_DISCONNECT = "supersocksr.ppp.android.ACTION_DISCONNECT"
        const val EXTRA_CONFIG = "config_json"
        const val EXTRA_VPN_OPTIONS = "vpn_options_json"
        private const val IPV6_BLOCK_ADDRESS = "fd00:6f70:656e:7070::2"

        @Volatile
        var instance: PppVpnService? = null
            private set

        var isRunning = false
            private set

        var currentState = 0
            private set
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnThread: Thread? = null

    // When ACTION_CONNECT arrives while the previous session is still tearing
    // down, we stash the new config here and the vpn thread's finally block
    // will replay it once isRunning=false. This makes "tap Stop -> tap Start"
    // feel instant from the user's POV instead of timing out at 30s.
    private var pendingConfig: String? = null
    private var pendingVpnOptions: String? = null

    private var linkStateThread: HandlerThread? = null
    private var linkStateHandler: Handler? = null
    private var heartbeatThread: HandlerThread? = null
    private var heartbeatHandler: Handler? = null
    private var connectStartedAtMs: Long = 0L
    private var lastNotificationText: String? = null
    private val snapshotOrdering = Any()
    private var lastSnapshotGeneration = -1L
    private var lastSnapshotMonotonicMs = -1L
    private var activeConfigJson: String? = null
    private var activeVpnOptionsJson: String? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var networkWasAvailable: Boolean = true
    private var lastNetworkReconnectAtMs: Long = 0L
    private val networkReconnectDebounceMs = 5000L
    private val linkStatePoller = object : Runnable {
        override fun run() {
            if (!isRunning) return
            val ls = try {
                libopenppp2.get_link_state()
            } catch (e: Throwable) {
                PppLog.write(this@PppVpnService, "get_link_state poller failed", e)
                6
            }
            publishLinkState(ls)
            // The heartbeat above is this poller's real job now that snapshots
            // are pushed from native; the read below is only a safety net.
            val runtimeSnapshot = try {
                libopenppp2.get_runtime_snapshot()
            } catch (e: Throwable) {
                PppLog.write(this@PppVpnService, "get_runtime_snapshot poller failed", e)
                null
            }
            if (runtimeSnapshot != null) {
                onRuntimeSnapshot(runtimeSnapshot)
            }
            linkStateHandler?.postDelayed(this, 1000L)
        }
    }
    private val heartbeatPoller = object : Runnable {
        override fun run() {
            if (!isRunning) return
            PppStateStore.touchHeartbeat(this@PppVpnService)
            heartbeatHandler?.postDelayed(this, 1000L)
        }
    }

    /**
     * Entry point for every snapshot, whether it was pushed from native or
     * read by the poller. Native pushes arrive on whichever thread produced
     * the transition and carry no cross-thread ordering guarantee, so they are
     * ordered here by the snapshot's own generation and timestamp. Routing the
     * poller through the same gate means a missed push is still picked up
     * within a second, and a duplicate costs nothing.
     */
    fun onRuntimeSnapshot(json: String) {
        if (json.isBlank()) return

        val root = try {
            JSONObject(json)
        } catch (_: Throwable) {
            return
        }

        val generation = root.optLong("generation", -1L)
        val monotonicMs = root.optLong("monotonic_ms", -1L)
        if (generation < 0L || monotonicMs < 0L) return
        // Ordering check and disk/notification publish must be one critical
        // section: a second thread can otherwise pass the gate after we bump
        // the watermark but before we finish writing, then land an older
        // payload on top of a newer one (idle/failed lost to stale connected).
        synchronized(snapshotOrdering) {
            if (generation < lastSnapshotGeneration) return
            if (generation == lastSnapshotGeneration && monotonicMs <= lastSnapshotMonotonicMs) {
                return
            }
            lastSnapshotGeneration = generation
            lastSnapshotMonotonicMs = monotonicMs
            publishRuntimeSnapshot(json)
        }
    }

    private fun publishRuntimeSnapshot(value: String) {
        PppStateStore.setRuntimeSnapshot(this, value)
        // Snapshot callbacks can run on the native executor. Calling
        // get_link_state() here would post back to that executor and wait,
        // deadlocking both the callback and the link-state poller.
        PppStateStore.touchHeartbeat(this)
        updateNotificationForSnapshot(value)
    }

    private fun publishLinkState(value: Int) {
        PppStateStore.setLinkState(this, value)
    }

    /**
     * The notification is a second state surface. Its text mirrors the status
     * labels the app derives from the same phase (see runtime_controls.dart),
     * so the two cannot disagree.
     */
    private fun updateNotificationForSnapshot(json: String) {
        val phase = try {
            JSONObject(json).optString("phase")
        } catch (_: Throwable) {
            return
        }
        if (phase.isEmpty() || phase == "idle") return
        val text = when (phase) {
            "connected" -> "已连接"
            "reconnecting" -> "重连中..."
            "stopping" -> "断开中..."
            "failed" -> "连接失败"
            "unknown" -> "未知状态"
            else -> "连接中..."
        }
        if (text == lastNotificationText) return
        lastNotificationText = text
        updateNotification(text)
    }

    private fun startLinkStatePoller() {
        if (linkStateThread != null) return
        lastNotificationText = null
        val t = HandlerThread("openppp2-linkstate").also { it.start() }
        linkStateThread = t
        val h = Handler(t.looper)
        linkStateHandler = h
        h.post(linkStatePoller)
    }

    private fun startHeartbeatPoller() {
        if (heartbeatThread != null) return
        val t = HandlerThread("openppp2-heartbeat").also { it.start() }
        heartbeatThread = t
        val h = Handler(t.looper)
        heartbeatHandler = h
        h.post(heartbeatPoller)
    }

    private fun stopHeartbeatPoller() {
        heartbeatHandler?.removeCallbacksAndMessages(null)
        heartbeatHandler = null
        heartbeatThread?.quitSafely()
        heartbeatThread = null
        PppStateStore.clearHeartbeat(this)
    }

    private fun stopLinkStatePoller() {
        try {
            libopenppp2.get_runtime_snapshot()?.let { onRuntimeSnapshot(it) }
        } catch (e: Throwable) {
            PppLog.write(this, "final get_runtime_snapshot failed", e)
        }
        linkStateHandler?.removeCallbacksAndMessages(null)
        linkStateHandler = null
        linkStateThread?.quitSafely()
        linkStateThread = null
        PppStateStore.clearLinkState(this)
        publishLinkState(6)
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
        createNotificationChannel()
        // If this process was freshly (re)started -- typically after a
        // native crash or after being killed while the tunnel was up -- any
        // link-state / service-state files on disk are stale and will make
        // the UI sit on "Initializing" forever. Reset them so the user
        // sees a clean disconnected state.
        PppStateStore.clearLinkState(this)
        PppStateStore.clearHeartbeat(this)
        PppStateStore.clearRuntimeSnapshot(this)
        PppStateStore.clearLastError(this)
        PppStateStore.set(this, 0)
        currentState = 0
        isRunning = false
        ensureGeoRulesAssets()
        NativeTelemetryTransport.install(applicationContext)
        resetNativeSession("onCreate")
        PppLog.write(this, "PppVpnService created (state cleared)")
    }

    private fun resetNativeSession(reason: String) {
        try {
            libopenppp2.stop()
        } catch (e: Throwable) {
            PppLog.write(this, "resetNativeSession stop failed ($reason)", e)
        }
        try {
            libopenppp2.clear_configure()
        } catch (e: Throwable) {
            PppLog.write(this, "resetNativeSession clear_configure failed ($reason)", e)
        }
    }

    /**
     * Drop a pre-bundled fallback copy of GeoIP.dat / GeoSite.dat into
     * `files/rules/` if the user does not already have a usable copy.
     *
     * Why: the native engine's `open_switcher` path is configured with
     * `./rules/GeoIP.dat`, `./rules/GeoSite.dat`. When those paths are
     * missing or are directories (we observed them mistakenly created as
     * empty directories on a previous run), `libopenppp2.run()` blocks
     * for ~60s trying to (re)download from `geoip-download-url` and the
     * UI sits on "Initializing" until the watchdog fires.
     *
     * The two .dat files are bundled under `assets/rules/` and are
     * copied here at most once per APK version. We treat anything that
     * is NOT a regular file at the destination (missing, or a stray
     * directory left over from earlier broken builds) as "needs copy",
     * deleting the stale entry first.
     */
    private fun ensureGeoRulesAssets() {
        try {
            val rulesDir = java.io.File(filesDir, "rules")
            if (!rulesDir.exists()) rulesDir.mkdirs()
            val pairs = listOf(
                "rules/geoip.dat" to "GeoIP.dat",
                "rules/geosite.dat" to "GeoSite.dat",
            )
            for ((assetPath, destName) in pairs) {
                val dest = java.io.File(rulesDir, destName)
                // Wipe stray directory placeholders (the bug that wedged
                // earlier sessions) so we can overwrite with a real file.
                if (dest.exists() && !dest.isFile) {
                    dest.deleteRecursively()
                }
                if (dest.isFile && dest.length() > 0L) continue
                assets.open(assetPath).use { input ->
                    java.io.FileOutputStream(dest).use { output ->
                        input.copyTo(output)
                    }
                }
                PppLog.write(this, "extracted asset $assetPath -> ${dest.absolutePath} (${dest.length()} bytes)")
            }
            // Also clean up the wrong-location stray dirs at filesDir root
            // that older builds created, so they stop confusing diagnostics.
            for (n in listOf("GeoIP.dat", "GeoSite.dat")) {
                val stray = java.io.File(filesDir, n)
                if (stray.exists() && !stray.isFile) {
                    stray.deleteRecursively()
                    PppLog.write(this, "removed stray $n at filesDir root")
                }
            }
        } catch (e: Throwable) {
            PppLog.write(this, "ensureGeoRulesAssets failed", e)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        try {
            PppLog.write(this, "onStartCommand action=${intent?.action}")
            when (intent?.action) {
                ACTION_CONNECT -> {
                    val config = intent.getStringExtra(EXTRA_CONFIG) ?: return START_NOT_STICKY
                    val vpnOptions = intent.getStringExtra(EXTRA_VPN_OPTIONS) ?: "{}"
                    startVpn(config, vpnOptions)
                }
                ACTION_DISCONNECT -> {
                    stopVpn()
                }
            }
        } catch (e: Throwable) {
            PppLog.write(this, "onStartCommand failed", e)
            notifyError("onStartCommand failed: ${e.message ?: e.javaClass.name}")
            notifyStateChanged(0)
            stopSelf()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopVpn()
        isRunning = false
        currentState = 0
        PppStateStore.set(this, 0)
        stopLinkStatePoller()
        stopHeartbeatPoller()
        stopNetworkMonitor()
        releaseWakeLock()
        activeConfigJson = null
        activeVpnOptionsJson = null
        vpnInterface?.close()
        vpnInterface = null
        instance = null
        super.onDestroy()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    private fun startVpn(configJson: String, vpnOptionsJson: String) {
        // A new attempt owns the mirrored state: the previous session's error
        // and snapshot carry a stale generation and must not be presented.
        PppStateStore.clearLastError(this)
        PppStateStore.clearRuntimeSnapshot(this)
        PppStateStore.clearHeartbeat(this)
        if (isRunning) {
            // A previous session is still live or wedged (common after the UI
            // process is killed while :vpn keeps running). Queue the new config
            // and tear down safely; the vpn thread finally block replays it.
            pendingConfig = configJson
            pendingVpnOptions = vpnOptionsJson
            if (currentState == 3) {
                PppLog.write(this, "ACTION_CONNECT while disconnecting -- restart queued")
            } else {
                PppLog.write(this, "ACTION_CONNECT while session active (state=$currentState) -- restart queued")
                stopVpn()
            }
            return
        }

        startForeground(NOTIFICATION_ID, buildNotification("正在连接..."))
        PppLog.write(this, "startForeground done")
        activeConfigJson = configJson
        activeVpnOptionsJson = vpnOptionsJson
        acquireWakeLock()
        startNetworkMonitor()
        connectStartedAtMs = android.os.SystemClock.elapsedRealtime()
        PppLog.write(this, "perf connect_requested")
        notifyStateChanged(1) // connecting

        try {
            // Set app configuration
            val options = JSONObject(vpnOptionsJson)
            val vpnIp = options.optString("tunIp", "10.0.0.2")
            val vpnMask = options.optString("tunMask", "255.255.255.0")
            val vpnPrefix = options.optInt("tunPrefix", 24)
            val route = options.optString("route", "0.0.0.0")
            val routePrefix = options.optInt("routePrefix", 0)
            val dns1 = options.optString("dns1", "8.8.8.8")
            val dns2 = options.optString("dns2", "8.8.4.4")
            val mtu = options.optInt("mtu", 1400)
            val mark = options.optInt("mark", 0)
            val mux = options.optInt("mux", 0)
            val vnet = options.optBoolean("vnet", false)
            val blockQuic = options.optBoolean("blockQuic", false)
            val staticMode = options.optBoolean("staticMode", false)
            val proxyOnly = options.optBoolean("proxyOnly", false)
            val bypassIpList = options.optString("bypassIpList", "")
            val dnsRulesList = options.optString("dnsRulesList", "")
            PppLog.write(
                this,
                "vpn options tunIp=$vpnIp tunMask=$vpnMask tunPrefix=$vpnPrefix route=$route/$routePrefix dns1=$dns1 dns2=$dns2 mtu=$mtu mark=$mark mux=$mux vnet=$vnet blockQuic=$blockQuic staticMode=$staticMode proxyOnly=$proxyOnly bypassIpList=${bypassIpList.isNotBlank()} dnsRulesList=${dnsRulesList.isNotBlank()}"
            )

            // Anchor relative paths inside the AppConfiguration JSON
            // (e.g. `./rules/GeoIP.dat`, `./generated/bypass-cn.txt`) to the
            // app's filesDir so the native GeoRuleGenerator can read/write
            // them. Default Android process CWD is `/`, which is read-only.
            val rootPath = filesDir.absolutePath
            val rootOk = try {
                libopenppp2.set_root_path(rootPath)
            } catch (_: UnsatisfiedLinkError) {
                // Older libopenppp2.so without set_root_path: silently ignore;
                // user must use absolute paths in DNS / Geo settings instead.
                false
            }
            PppLog.write(this, "set_root_path path=$rootPath ok=$rootOk")

            val configResult = libopenppp2.set_app_configuration(configJson)
            PppLog.write(this, "set_app_configuration result=$configResult")
            if (configResult != 0) {
                notifyError("set_app_configuration failed: $configResult, error: ${libopenppp2.get_last_error_text()}")
                notifyStateChanged(0) // disconnected
                stopForeground(true)
                stopSelf()
                return
            }

            // Sync VPN DNS servers into native vdns upstream list (gateway DNS path).
            run {
                val configRoot = try {
                    JSONObject(configJson)
                } catch (_: Throwable) {
                    JSONObject()
                }
                val udpDns = configRoot.optJSONObject("udp")?.optJSONObject("dns")
                val turbo = udpDns?.optBoolean("turbo", false) ?: false
                val ttl = (udpDns?.optInt("ttl", 60) ?: 60).coerceAtLeast(1)
                val dnsBcl = listOf(dns1, dns2).filter { it.isNotBlank() }.joinToString(",")
                if (dnsBcl.isNotBlank()) {
                    val dnsBclOk = libopenppp2.set_dns_bcl(turbo, ttl, dnsBcl)
                    PppLog.write(this, "set_dns_bcl turbo=$turbo ttl=$ttl dns=$dnsBcl ok=$dnsBclOk")
                }
            }

            // Native bypass and DNS policy applies in both TUN and proxy-only modes.
            if (bypassIpList.isNotBlank()) {
                val bypassResult = libopenppp2.set_bypass_ip_list(bypassIpList)
                PppLog.write(this, "set_bypass_ip_list result=$bypassResult")
            }
            if (dnsRulesList.isNotBlank()) {
                val dnsResult = libopenppp2.set_dns_rules_list(dnsRulesList)
                PppLog.write(this, "set_dns_rules_list result=$dnsResult")
            }

            val builder = Builder()
                .setSession("OpenPPP2")
                .addAddress(vpnIp, vpnPrefix)
                .allowFamily(OsConstants.AF_INET)
                .setMtu(mtu)
                .setBlocking(true)

            if (proxyOnly) {
                builder.addRoute(vpnIp, vpnPrefix)
            } else {
                builder.addRoute(route, routePrefix)
            }

            if (!proxyOnly) {
                try {
                    builder.addAddress(IPV6_BLOCK_ADDRESS, 128)
                    builder.addRoute("::", 0)
                    builder.allowFamily(OsConstants.AF_INET6)
                    PppLog.write(this, "IPv6 leak protection active (capturing ::/0)")
                } catch (e: Throwable) {
                    val reason = "IPv6 leak protection setup failed: ${e.message ?: e.javaClass.name}"
                    PppLog.write(this, reason, e)
                    notifyError(reason)
                    notifyStateChanged(0)
                    stopForeground(true)
                    stopSelf()
                    return
                }
            } else {
                PppLog.write(this, "IPv6 capture and leak protection disabled in proxy-only mode")
            }

            if (!proxyOnly) {
                if (dns1.isNotBlank()) {
                    builder.addDnsServer(dns1)
                }
                if (dns2.isNotBlank()) {
                    builder.addDnsServer(dns2)
                }
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP && mark != 0) {
                builder.setConfigureIntent(buildConfigureIntent())
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }

            // ---- Per-app proxy ----
            // 'allow' mode = only the listed packages get proxied; 'deny' mode
            // = every other app is proxied except the listed ones. We always
            // exclude our own package so we never recurse through the tunnel.
            val perAppEnabled = options.optBoolean("perAppProxyEnabled", false)
            val perAppMode = options.optString("perAppProxyMode", "allow")
            val perAppApps = options.optJSONArray("perAppProxyApps")
            val perAppPackages = ArrayList<String>()
            if (perAppApps != null) {
                for (i in 0 until perAppApps.length()) {
                    val pkg = perAppApps.optString(i, "")
                    if (pkg.isNotBlank()) perAppPackages.add(pkg)
                }
            }
            if (perAppEnabled && perAppPackages.isNotEmpty()) {
                var added = 0
                var skipped = 0
                for (pkg in perAppPackages) {
                    if (pkg == this.packageName) {
                        skipped++
                        continue
                    }
                    try {
                        if (perAppMode == "deny") {
                            builder.addDisallowedApplication(pkg)
                        } else {
                            builder.addAllowedApplication(pkg)
                        }
                        added++
                    } catch (e: PackageManager.NameNotFoundException) {
                        // Uninstalled while we were holding the snapshot --
                        // tolerate and keep going.
                        skipped++
                        PppLog.write(this, "per-app proxy: package not found $pkg")
                    } catch (e: Throwable) {
                        skipped++
                        PppLog.write(this, "per-app proxy: failed to add $pkg", e)
                    }
                }
                // Always exclude self in allow mode -- the system would already
                // exclude the active VPN app, but be explicit so the picker UI
                // matches behaviour.
                if (perAppMode == "deny") {
                    try {
                        builder.addDisallowedApplication(this.packageName)
                    } catch (_: Throwable) { /* ignore */ }
                }
                PppLog.write(
                    this,
                    "per-app proxy mode=$perAppMode applied=$added skipped=$skipped total=${perAppPackages.size}"
                )
            } else {
                PppLog.write(this, "per-app proxy disabled (or no packages selected)")
            }

            // ---- System HTTP proxy ----
            // Do not publish the native proxy through VpnService.Builder. The
            // native listener cannot own its port until after establish() has
            // supplied the TUN descriptor and run() has started, so publishing
            // it here would let another local app win the bind race.
            val systemHttpProxy = options.optBoolean("autoAppendApps", false) || proxyOnly
            if (systemHttpProxy) {
                PppLog.write(
                    this,
                    "system http proxy disabled: native listener ownership is unavailable before VPN setup"
                )
            }

            vpnInterface = builder.establish()
            PppLog.write(this, "builder.establish result=${vpnInterface != null}")
            if (vpnInterface == null) {
                notifyError("Failed to establish VPN interface")
                notifyStateChanged(0) // disconnected
                stopForeground(true)
                stopSelf()
                return
            }

            // detachFd() transfers ownership of the file descriptor to native code.
            // Using .fd directly causes fdsan SIGABRT when native close() runs because
            // ParcelFileDescriptor still claims ownership.
            val tunFd = vpnInterface!!.detachFd()
            vpnInterface = null
            PppLog.write(this, "detached tun fd=$tunFd")

            // Set network interface for native layer
            val niResult = libopenppp2.set_network_interface(
                tunFd,
                mux,
                vnet,
                blockQuic,
                staticMode,
                vpnIp,
                vpnMask
            )
            PppLog.write(this, "set_network_interface result=$niResult")
            if (niResult != 0) {
                notifyError("set_network_interface failed: $niResult, error: ${libopenppp2.get_last_error_text()}")
                vpnInterface?.close()
                vpnInterface = null
                notifyStateChanged(0)
                stopForeground(true)
                stopSelf()
                return
            }

            // Start VPN in background thread (run() is blocking)
            PppLog.write(this, "before libopenppp2.run(0)")
            isRunning = true
            startHeartbeatPoller()
            // Begin polling native link state across processes (PppStateStore
            // file-backed) so the UI process can read the real handshake state.
            startLinkStatePoller()
            // Use an 8 MiB stack (default JVM thread stack on Android is
            // ~1 MiB, which is too small for boost::asio's deep handler
            // chains and the cascade of shared_ptr destructions that runs
            // when a connection is torn down -- we have observed
            // SI_KERNEL fault 0x0 (stack-guard hit) inside
            // ppp::function::Callable<...>::__on_zero_shared while the
            // VPN was happily forwarding traffic, triggered by a peer
            // RST that posted VirtualEthernetTcpipConnection::Dispose and
            // then deep-released the connection's Timer callbacks).
            vpnThread = Thread(null, Runnable {
                try {
                    PppLog.write(this, "vpnThread started, calling run(0)")
                    val result = libopenppp2.run(0)
                    PppLog.write(this, "libopenppp2.run returned=$result")
                    if (result != 0) {
                        PppLog.write(this, "libopenppp2 last error=${libopenppp2.get_last_error_text()}")
                    }
                    Log.i(TAG, "libopenppp2.run() returned: $result")
                } catch (e: Throwable) {
                    Log.e(TAG, "VPN thread exception", e)
                    PppLog.write(this, "VPN thread exception", e)
                    notifyError("VPN thread exception: ${e.message ?: e.javaClass.name}")
                } finally {
                    isRunning = false
                    stopLinkStatePoller()
                    stopHeartbeatPoller()
                    stopNetworkMonitor()
                    releaseWakeLock()
                    vpnInterface?.close()
                    vpnInterface = null
                    val pConfig = pendingConfig
                    val pOptions = pendingVpnOptions
                    pendingConfig = null
                    pendingVpnOptions = null
                    if (pConfig != null) {
                        // A reconnect was queued while we were tearing down.
                        // Replay it on the main looper so the new run() runs
                        // on a fresh worker thread and we keep the foreground
                        // service alive (no stopForeground/stopSelf here).
                        PppLog.write(this, "replaying queued ACTION_CONNECT after teardown")
                        Handler(Looper.getMainLooper()).post {
                            startVpn(pConfig, pOptions ?: "{}")
                        }
                    } else {
                        activeConfigJson = null
                        activeVpnOptionsJson = null
                        notifyStateChanged(0) // disconnected
                        stopForeground(true)
                        stopSelf()
                    }
                }
            }, "openppp2-vpn-thread", 32L * 1024 * 1024).also { it.start() }

        } catch (e: Throwable) {
            Log.e(TAG, "startVpn exception", e)
            PppLog.write(this, "startVpn exception", e)
            notifyError("startVpn exception: ${e.message ?: e.javaClass.name}")
            notifyStateChanged(0)
            stopForeground(true)
            stopSelf()
        }
    }

    private fun stopVpn() {
        PppLog.write(this, "stopVpn requested, isRunning=$isRunning")
        if (!isRunning) {
            resetNativeSession("stopVpn_idle")
            PppStateStore.set(this, 0)
            stopLinkStatePoller()
            stopHeartbeatPoller()
            currentState = 0
            return
        }

        notifyStateChanged(3) // disconnecting
        try {
            libopenppp2.stop()
        } catch (e: Throwable) {
            Log.e(TAG, "stop exception", e)
            PppLog.write(this, "stop exception", e)
        }
        // The vpnThread will exit after run() returns, cleaning up in finally block
    }

    fun onStarted(key: Int) {
        Log.i(TAG, "VPN started with key: $key")
        val connectElapsedMs = if (connectStartedAtMs > 0L) {
            android.os.SystemClock.elapsedRealtime() - connectStartedAtMs
        } else {
            -1L
        }
        PppLog.write(this, "perf connect_established_ms=$connectElapsedMs")
        Log.i(TAG, "perf connect_established_ms=$connectElapsedMs")
        PppLog.write(this, "onStarted key=$key")
        PppLog.write(this, "VPN started with key=$key")
        publishLinkState(0)
        notifyStateChanged(2) // connected
    }

    private fun notifyStateChanged(state: Int) {
        currentState = state
        PppStateStore.set(this, state)
    }

    private fun notifyError(message: String) {
        Log.e(TAG, message)
        PppLog.write(this, message)
        PppStateStore.setLastError(this, message)
    }

    private fun buildConfigureIntent(): PendingIntent {
        return PendingIntent.getActivity(
            this, 1,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "OpenPPP2 VPN",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "VPN service notification"
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        return builder
            .setContentTitle("OpenPPP2")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun acquireWakeLock() {
        if (wakeLock?.isHeld == true) return
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "openppp2:vpn").apply {
            setReferenceCounted(false)
            acquire()
        }
        PppLog.write(this, "wake lock acquired")
    }

    private fun releaseWakeLock() {
        wakeLock?.let { lock ->
            if (lock.isHeld) {
                lock.release()
                PppLog.write(this, "wake lock released")
            }
        }
        wakeLock = null
    }

    private fun startNetworkMonitor() {
        if (networkCallback != null) return
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        connectivityManager = cm
        networkWasAvailable = isNetworkValidated(cm)
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onLost(network: Network) {
                networkWasAvailable = false
                PppLog.write(this@PppVpnService, "network lost")
            }

            override fun onAvailable(network: Network) {
                maybeReconnectAfterNetworkChange("available")
            }

            override fun onCapabilitiesChanged(
                network: Network,
                networkCapabilities: NetworkCapabilities
            ) {
                if (networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                ) {
                    maybeReconnectAfterNetworkChange("validated")
                }
            }
        }
        networkCallback = callback
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                cm.registerDefaultNetworkCallback(callback)
            } else {
                val request = NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .build()
                cm.registerNetworkCallback(request, callback)
            }
            PppLog.write(this, "network monitor started")
        } catch (e: Throwable) {
            PppLog.write(this, "network monitor start failed", e)
            networkCallback = null
            connectivityManager = null
        }
    }

    private fun stopNetworkMonitor() {
        val callback = networkCallback
        networkCallback = null
        if (callback != null) {
            try {
                connectivityManager?.unregisterNetworkCallback(callback)
                PppLog.write(this, "network monitor stopped")
            } catch (e: Throwable) {
                PppLog.write(this, "network monitor stop failed", e)
            }
        }
        connectivityManager = null
        networkWasAvailable = true
    }

    private fun isNetworkValidated(cm: ConnectivityManager): Boolean {
        val network = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(network) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
    }

    private fun maybeReconnectAfterNetworkChange(reason: String) {
        if (!isRunning) return
        val wasAvailable = networkWasAvailable
        networkWasAvailable = true
        if (wasAvailable) return

        val now = SystemClock.elapsedRealtime()
        if (now - lastNetworkReconnectAtMs < networkReconnectDebounceMs) return
        lastNetworkReconnectAtMs = now

        val config = activeConfigJson ?: return
        PppLog.write(this, "network recovered ($reason) -> reconnecting VPN")
        pendingConfig = config
        pendingVpnOptions = activeVpnOptionsJson ?: "{}"
        stopVpn()
    }
}
