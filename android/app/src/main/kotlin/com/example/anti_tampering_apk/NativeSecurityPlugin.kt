package com.example.anti_tampering_apk

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.io.File
import java.security.MessageDigest

/**
 * Flutter Method Channel plugin for native security detection.
 *
 * Dispatches calls from Dart to individual SecurityDetectors methods.
 * Each detection vector runs independently to prevent single-hook bypass.
 */
class NativeSecurityPlugin : FlutterPlugin, MethodCallHandler {

    private lateinit var channel: MethodChannel
    private lateinit var detectors: SecurityDetectors
    private lateinit var appContext: Context

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(binding.binaryMessenger, "com.example.security/native")
        channel.setMethodCallHandler(this)
        appContext = binding.applicationContext
        detectors = SecurityDetectors(appContext)
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "runAllChecks" -> {
                try {
                    val checks = runAllChecks()
                    result.success(checks)
                } catch (e: Exception) {
                    result.error("SECURITY_CHECK_ERROR", e.message, null)
                }
            }

            "runCheck" -> {
                val checkName = call.argument<String>("check")
                if (checkName == null) {
                    result.error("INVALID_ARG", "Missing 'check' argument", null)
                    return
                }
                try {
                    val checkResult = runSingleCheck(checkName)
                    result.success(checkResult)
                } catch (e: Exception) {
                    result.error("SECURITY_CHECK_ERROR", e.message, null)
                }
            }

            "getEnvironmentInfo" -> {
                try {
                    val info = detectors.getEnvironmentInfo()
                    result.success(info)
                } catch (e: Exception) {
                    result.error("ENV_INFO_ERROR", e.message, null)
                }
            }

            "getApkInfo" -> {
                try {
                    val info = getApkInfo()
                    result.success(info)
                } catch (e: Exception) {
                    result.error("APK_INFO_ERROR", e.message, null)
                }
            }

            else -> result.notImplemented()
        }
    }

    /**
     * Execute all 9 detection vectors and return aggregated results.
     * Each vector runs independently — failures are isolated.
     */
    private fun runAllChecks(): Map<String, Any> {
        return mapOf(
            "frida_detected" to safeCheck { detectors.detectFrida() },
            "root_detected" to safeCheck { detectors.detectRoot() },
            "signature_valid" to safeCheck { detectors.verifySignature() },
            "dex_integrity_valid" to safeCheck { detectors.verifyDexIntegrity() },
            "xposed_detected" to safeCheck { detectors.detectXposed() },
            "debugger_attached" to safeCheck { detectors.detectDebugger() },
            "emulator_detected" to safeCheck { detectors.detectEmulator() },
            "hook_detected" to safeCheck { detectors.detectHooks() },
            "cert_pinning_bypassed" to safeCheck { detectors.checkCertPinningBypass() }
        )
    }

    /**
     * Run a single named check.
     */
    private fun runSingleCheck(name: String): Boolean {
        return when (name) {
            "frida" -> detectors.detectFrida()
            "root" -> detectors.detectRoot()
            "signature" -> detectors.verifySignature()
            "dex_integrity" -> detectors.verifyDexIntegrity()
            "xposed" -> detectors.detectXposed()
            "debugger" -> detectors.detectDebugger()
            "emulator" -> detectors.detectEmulator()
            "hooks" -> detectors.detectHooks()
            "cert_pinning" -> detectors.checkCertPinningBypass()
            else -> false
        }
    }

    /**
     * Safely execute a check — if it throws, return the "unsafe" default.
     */
    private fun safeCheck(block: () -> Boolean): Boolean {
        return try {
            block()
        } catch (e: Exception) {
            // If a check itself fails, assume the worst
            true
        }
    }

    /**
     * Collect comprehensive APK metadata for integrity analysis.
     */
    @Suppress("DEPRECATION")
    private fun getApkInfo(): Map<String, Any> {
        val result = mutableMapOf<String, Any>()

        try {
            val pm = appContext.packageManager
            val packageName = appContext.packageName

            // Package info
            val pkgInfo = pm.getPackageInfo(packageName, 0)
            result["package_name"] = packageName
            result["version_name"] = pkgInfo.versionName ?: "unknown"
            result["version_code"] = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pkgInfo.longVersionCode
            } else {
                pkgInfo.versionCode.toLong()
            }
            result["first_install_time"] = pkgInfo.firstInstallTime
            result["last_update_time"] = pkgInfo.lastUpdateTime

            // APK hash
            val apkPath = appContext.packageCodePath
            val apkFile = File(apkPath)
            if (apkFile.exists()) {
                val md = MessageDigest.getInstance("SHA-256")
                apkFile.inputStream().use { input ->
                    val buffer = ByteArray(8192)
                    var bytesRead: Int
                    while (input.read(buffer).also { bytesRead = it } != -1) {
                        md.update(buffer, 0, bytesRead)
                    }
                }
                val digest = md.digest()
                result["apk_hash"] = digest.joinToString("") { "%02x".format(it) }
                result["apk_size"] = apkFile.length()
            }

            // Signature fingerprint
            val sigInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
            } else {
                pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
            }
            val sigs = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                sigInfo.signingInfo?.apkContentsSigners
            } else {
                sigInfo.signatures
            }
            if (!sigs.isNullOrEmpty()) {
                val certBytes = sigs[0].toByteArray()
                val certMd = MessageDigest.getInstance("SHA-256")
                val certDigest = certMd.digest(certBytes)
                result["cert_fingerprint"] = certDigest.joinToString("") { "%02x".format(it) }
            }

            // Declared permissions
            val permInfo = pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
            val permissions = permInfo.requestedPermissions?.toList() ?: emptyList()
            result["permissions"] = permissions
            result["permissions_count"] = permissions.size

            // Sensitive permissions detection
            val sensitivePerms = listOf(
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.READ_CONTACTS",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.READ_CALL_LOG",
                "android.permission.READ_PHONE_STATE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.INSTALL_PACKAGES",
                "android.permission.REQUEST_INSTALL_PACKAGES"
            )
            val foundSensitive = permissions.filter { it in sensitivePerms }
            result["sensitive_permissions"] = foundSensitive
            result["sensitive_permissions_count"] = foundSensitive.size

            // Installer info
            val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(packageName).installingPackageName
            } else {
                pm.getInstallerPackageName(packageName)
            }
            result["installer"] = installer ?: "unknown (sideloaded)"

            // Debuggable flag
            val appInfo = pm.getApplicationInfo(packageName, 0)
            result["is_debuggable"] = (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0

        } catch (e: Exception) {
            result["error"] = e.message ?: "Unknown error"
        }

        return result
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }
}
