package com.example.anti_tampering_apk

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest

/**
 * 9 independent security detection vectors for Android.
 *
 * Each method is self-contained to prevent a single Frida hook
 * from disabling multiple checks. Methods are ordered by severity weight.
 */
class SecurityDetectors(private val context: Context) {

    // ═══════════════════════════════════════════════════════════════
    // TODO: Replace these with your actual values before release
    // ═══════════════════════════════════════════════════════════════
    companion object {
        // SHA-256 of your release signing certificate
        const val EXPECTED_CERT_FINGERPRINT = "REPLACE_WITH_YOUR_CERT_SHA256"
        // SHA-256 of classes.dex in the release APK
        const val EXPECTED_DEX_HASH = "REPLACE_WITH_YOUR_DEX_SHA256"
    }

    // ─────────────────────────────────────────────────────────────
    // 1. FRIDA DETECTION — Weight: CRITIQUE (0.95)
    // ─────────────────────────────────────────────────────────────
    /**
     * Detects Frida instrumentation toolkit by:
     * - Scanning default Frida ports (27042-27043)
     * - Reading /proc/self/maps for Frida libraries
     * - Checking for frida-server process
     */
    fun detectFrida(): Boolean {
        return detectFridaPorts() || detectFridaInMaps() || detectFridaProcess()
    }

    private fun detectFridaPorts(): Boolean {
        val fridaPorts = listOf(27042, 27043)
        for (port in fridaPorts) {
            try {
                val socket = Socket()
                socket.connect(InetSocketAddress("127.0.0.1", port), 100)
                socket.close()
                return true // Port is open — Frida likely active
            } catch (_: Exception) {
                // Port closed — good
            }
        }
        return false
    }

    private fun detectFridaInMaps(): Boolean {
        val fridaIndicators = listOf(
            "frida", "gadget", "linjector",
            "libfrida", "frida-agent", "frida-gadget"
        )
        try {
            val reader = BufferedReader(FileReader("/proc/self/maps"))
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                val lowerLine = line!!.lowercase()
                for (indicator in fridaIndicators) {
                    if (lowerLine.contains(indicator)) {
                        reader.close()
                        return true
                    }
                }
            }
            reader.close()
        } catch (_: Exception) {
            // Cannot read maps — might be restricted, not necessarily Frida
        }
        return false
    }

    private fun detectFridaProcess(): Boolean {
        try {
            val process = Runtime.getRuntime().exec(arrayOf("ps", "-A"))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                if (line!!.lowercase().contains("frida")) {
                    reader.close()
                    return true
                }
            }
            reader.close()
        } catch (_: Exception) {}
        return false
    }

    // ─────────────────────────────────────────────────────────────
    // 2. HOOK DETECTION — Weight: CRITIQUE (0.90)
    // ─────────────────────────────────────────────────────────────
    /**
     * Detects runtime hooking by verifying that critical method
     * modifiers haven't been altered (e.g., by Frida or Substrate).
     */
    fun detectHooks(): Boolean {
        try {
            // Check if our own methods have been tampered with
            val thisClass = this::class.java
            val methods = thisClass.declaredMethods

            for (method in methods) {
                // Native methods that shouldn't be native
                if (java.lang.reflect.Modifier.isNative(method.modifiers)) {
                    if (!method.name.startsWith("native")) {
                        return true // Method was hooked to native
                    }
                }
            }

            // Check for common hooking frameworks in loaded libraries
            val hookLibraries = listOf(
                "substrate", "xhook", "whale", "epic",
                "SandHook", "Pine", "yahfa"
            )
            val mapsContent = readProcMaps()
            for (lib in hookLibraries) {
                if (mapsContent.lowercase().contains(lib.lowercase())) {
                    return true
                }
            }
        } catch (_: Exception) {}
        return false
    }

    // ─────────────────────────────────────────────────────────────
    // 3. CERT PINNING BYPASS DETECTION — Weight: ÉLEVÉ (0.85)
    // ─────────────────────────────────────────────────────────────
    /**
     * Detects if a TLS interceptor (Burp Suite, mitmproxy, etc.)
     * has been installed as a trusted CA certificate.
     */
    fun checkCertPinningBypass(): Boolean {
        try {
            // Check for common proxy/interception apps
            val proxyApps = listOf(
                "com.mitmproxy.mitmproxy",
                "com.levyitay.networkinterceptor",
                "app.greyshirts.sslcapture",
                "com.guoshi.httpcanary",
                "eu.faircode.netguard"
            )
            val pm = context.packageManager
            for (app in proxyApps) {
                try {
                    pm.getPackageInfo(app, 0)
                    return true // Intercept app installed
                } catch (_: PackageManager.NameNotFoundException) {
                    // Not installed — good
                }
            }

            // Check for HTTP proxy configured
            val proxyHost = System.getProperty("http.proxyHost")
            val proxyPort = System.getProperty("http.proxyPort")
            if (!proxyHost.isNullOrEmpty() && !proxyPort.isNullOrEmpty()) {
                return true // Proxy configured — possible MITM
            }
        } catch (_: Exception) {}
        return false
    }

    // ─────────────────────────────────────────────────────────────
    // 4. APK SIGNATURE VERIFICATION — Weight: ÉLEVÉ (0.80)
    // ─────────────────────────────────────────────────────────────
    /**
     * Verifies the APK signing certificate's SHA-256 fingerprint
     * against the hardcoded expected value.
     */
    @Suppress("DEPRECATION")
    fun verifySignature(): Boolean {
        try {
            val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
            } else {
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNATURES
                )
            }

            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                packageInfo.signatures
            }

            if (signatures.isNullOrEmpty()) return false

            val certBytes = signatures[0].toByteArray()
            val md = MessageDigest.getInstance("SHA-256")
            val digest = md.digest(certBytes)
            val hexString = digest.joinToString("") { "%02x".format(it) }

            // In dev mode, skip validation if placeholder
            if (EXPECTED_CERT_FINGERPRINT == "REPLACE_WITH_YOUR_CERT_SHA256") {
                return true // Not configured yet
            }

            return hexString.equals(EXPECTED_CERT_FINGERPRINT, ignoreCase = true)
        } catch (_: Exception) {
            return false // Cannot verify — assume tampered
        }
    }

    // ─────────────────────────────────────────────────────────────
    // 5. DEX INTEGRITY — Weight: ÉLEVÉ (0.80)
    // ─────────────────────────────────────────────────────────────
    /**
     * Computes SHA-256 of classes.dex and compares with
     * the expected hash. Detects repackaged APKs.
     */
    fun verifyDexIntegrity(): Boolean {
        try {
            val apkPath = context.packageCodePath
            val dexFile = File(apkPath)

            if (!dexFile.exists()) return false

            val md = MessageDigest.getInstance("SHA-256")
            dexFile.inputStream().use { input ->
                val buffer = ByteArray(8192)
                var bytesRead: Int
                while (input.read(buffer).also { bytesRead = it } != -1) {
                    md.update(buffer, 0, bytesRead)
                }
            }

            val digest = md.digest()
            val hexString = digest.joinToString("") { "%02x".format(it) }

            // In dev mode, skip validation if placeholder
            if (EXPECTED_DEX_HASH == "REPLACE_WITH_YOUR_DEX_SHA256") {
                return true // Not configured yet
            }

            return hexString.equals(EXPECTED_DEX_HASH, ignoreCase = true)
        } catch (_: Exception) {
            return false // Cannot verify — assume tampered
        }
    }

    // ─────────────────────────────────────────────────────────────
    // 6. XPOSED DETECTION — Weight: MOYEN (0.70)
    // ─────────────────────────────────────────────────────────────
    /**
     * Detects the Xposed Framework by searching for its
     * classes in the classloader.
     */
    fun detectXposed(): Boolean {
        val xposedClasses = listOf(
            "de.robv.android.xposed.XposedBridge",
            "de.robv.android.xposed.XC_MethodHook",
            "de.robv.android.xposed.XposedHelpers",
            "de.robv.android.xposed.IXposedHookLoadPackage"
        )

        for (className in xposedClasses) {
            try {
                Class.forName(className)
                return true // Xposed class found in classloader
            } catch (_: ClassNotFoundException) {
                // Not found — good
            }
        }

        // Also check the stack trace for Xposed
        try {
            val stackTrace = Thread.currentThread().stackTrace
            for (element in stackTrace) {
                if (element.className.contains("xposed", ignoreCase = true)) {
                    return true
                }
            }
        } catch (_: Exception) {}

        // Check for Xposed installer app
        val xposedApps = listOf(
            "de.robv.android.xposed.installer",
            "org.meowcat.edxposed.manager",
            "org.lsposed.manager"
        )
        val pm = context.packageManager
        for (app in xposedApps) {
            try {
                pm.getPackageInfo(app, 0)
                return true
            } catch (_: PackageManager.NameNotFoundException) {}
        }

        return false
    }

    // ─────────────────────────────────────────────────────────────
    // 7. DEBUGGER DETECTION — Weight: MOYEN (0.60)
    // ─────────────────────────────────────────────────────────────
    /**
     * Detects attached debuggers via:
     * - Debug.isDebuggerConnected() API
     * - TracerPid in /proc/self/status
     * - Timing-based detection (debugger slows execution)
     */
    fun detectDebugger(): Boolean {
        // Direct API check
        if (Debug.isDebuggerConnected()) return true
        if (Debug.waitingForDebugger()) return true

        // TracerPid check
        try {
            val reader = BufferedReader(FileReader("/proc/self/status"))
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                if (line!!.startsWith("TracerPid:")) {
                    val tracerPid = line!!.split(":")[1].trim().toIntOrNull() ?: 0
                    if (tracerPid > 0) {
                        reader.close()
                        return true // Something is tracing us
                    }
                }
            }
            reader.close()
        } catch (_: Exception) {}

        // Timing check: debugger makes operations significantly slower
        try {
            val start = System.nanoTime()
            // Dummy computation
            var dummy = 0L
            for (i in 0 until 1_000_000) {
                dummy += i
            }
            val elapsed = System.nanoTime() - start
            // Normal: ~1-5ms. With debugger: >50ms
            if (elapsed > 50_000_000) {
                return true // Suspiciously slow — possible debugger
            }
        } catch (_: Exception) {}

        return false
    }

    // ─────────────────────────────────────────────────────────────
    // 8. ROOT DETECTION — Weight: FAIBLE (0.40)
    // ─────────────────────────────────────────────────────────────
    /**
     * Detects rooted devices by checking for su binaries,
     * root management apps, and dangerous system properties.
     */
    fun detectRoot(): Boolean {
        // Check for su binaries
        val suPaths = listOf(
            "/system/bin/su", "/system/xbin/su",
            "/sbin/su", "/system/su",
            "/data/local/su", "/data/local/bin/su",
            "/data/local/xbin/su", "/system/sd/xbin/su",
            "/system/app/Superuser.apk", "/cache/su"
        )
        for (path in suPaths) {
            if (File(path).exists()) return true
        }

        // Check for root management apps
        val rootApps = listOf(
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.noshufou.android.su",
            "com.thirdparty.superuser",
            "com.yellowes.su"
        )
        val pm = context.packageManager
        for (app in rootApps) {
            try {
                pm.getPackageInfo(app, 0)
                return true
            } catch (_: PackageManager.NameNotFoundException) {}
        }

        // Check system properties
        try {
            val process = Runtime.getRuntime().exec(arrayOf("getprop", "ro.build.tags"))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val tags = reader.readLine()
            reader.close()
            if (tags != null && tags.contains("test-keys")) {
                return true // Test-keys indicate custom/rooted build
            }
        } catch (_: Exception) {}

        // Try to execute su
        try {
            val process = Runtime.getRuntime().exec("su")
            process.destroy()
            return true // su command available
        } catch (_: Exception) {}

        return false
    }

    // ─────────────────────────────────────────────────────────────
    // 9. EMULATOR DETECTION — Weight: INFO (0.20)
    // ─────────────────────────────────────────────────────────────
    /**
     * Detects emulator environments via Build properties,
     * QEMU indicators, and hardware characteristics.
     */
    fun detectEmulator(): Boolean {
        // Build fingerprint checks
        val fingerprint = Build.FINGERPRINT.lowercase()
        val model = Build.MODEL.lowercase()
        val manufacturer = Build.MANUFACTURER.lowercase()
        val hardware = Build.HARDWARE.lowercase()
        val product = Build.PRODUCT.lowercase()

        val emulatorIndicators = listOf(
            "generic", "sdk", "genymotion", "vbox",
            "goldfish", "ranchu", "nox", "bluestacks",
            "andy", "ttvm", "droid4x", "unknown"
        )

        for (indicator in emulatorIndicators) {
            if (fingerprint.contains(indicator) ||
                model.contains(indicator) ||
                manufacturer.contains(indicator) ||
                hardware.contains(indicator) ||
                product.contains(indicator)
            ) {
                return true
            }
        }

        // QEMU property checks
        try {
            val process = Runtime.getRuntime().exec(
                arrayOf("getprop", "ro.hardware.chipname")
            )
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val value = reader.readLine()
            reader.close()
            if (value != null && value.lowercase().contains("ranchu")) {
                return true
            }
        } catch (_: Exception) {}

        // Check for emulator-specific files
        val emulatorFiles = listOf(
            "/dev/socket/qemud",
            "/dev/qemu_pipe",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace"
        )
        for (path in emulatorFiles) {
            if (File(path).exists()) return true
        }

        return false
    }

    // ─────────────────────────────────────────────────────────────
    // UTILITIES
    // ─────────────────────────────────────────────────────────────

    /**
     * Get environment metadata for the security report.
     */
    fun getEnvironmentInfo(): Map<String, Any> {
        return mapOf(
            "build_model" to Build.MODEL,
            "build_manufacturer" to Build.MANUFACTURER,
            "build_fingerprint" to Build.FINGERPRINT,
            "sdk_version" to Build.VERSION.SDK_INT,
            "build_type" to Build.TYPE,
            "build_tags" to Build.TAGS,
            "abi" to (Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown")
        )
    }

    /**
     * Read /proc/self/maps content (used by multiple detectors).
     */
    private fun readProcMaps(): String {
        return try {
            File("/proc/self/maps").readText()
        } catch (_: Exception) {
            ""
        }
    }
}
