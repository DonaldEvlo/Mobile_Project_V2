import 'package:flutter/services.dart';
import 'package:logger/logger.dart';

/// Collects APK metadata from the native Android layer.
///
/// Uses the MethodChannel to query the Kotlin NativeSecurityPlugin
/// for APK hash, signature, permissions, and other integrity data.
class ApkInfoCollector {
  static const _channel = MethodChannel('com.example.security/native');
  final _log = Logger(printer: PrettyPrinter(methodCount: 0));

  /// Cached APK info to avoid repeated native calls.
  Map<String, dynamic>? _cachedInfo;

  /// Collect all APK metadata from the native layer.
  Future<ApkInfo> collectApkInfo() async {
    if (_cachedInfo != null) {
      return ApkInfo.fromJson(_cachedInfo!);
    }

    try {
      final result = await _channel.invokeMethod<Map>('getApkInfo');
      if (result == null) {
        _log.w('getApkInfo returned null');
        return ApkInfo.empty();
      }
      _cachedInfo = Map<String, dynamic>.from(result);
      return ApkInfo.fromJson(_cachedInfo!);
    } on PlatformException catch (e) {
      _log.e('Failed to collect APK info: ${e.message}');
      return ApkInfo.empty();
    } on MissingPluginException {
      _log.w('Native plugin not available — cannot collect APK info');
      return ApkInfo.empty();
    }
  }

  /// Collect info for an external APK file by path.
  Future<ApkInfo> getExternalApkInfo(String path) async {
    try {
      final result = await _channel.invokeMethod<Map>(
        'getApkFileDetails',
        {'path': path},
      );
      if (result == null) {
        return ApkInfo.empty();
      }
      return ApkInfo.fromJson(Map<String, dynamic>.from(result));
    } on PlatformException catch (e) {
      _log.e('Failed to scan external APK: ${e.message}');
      return ApkInfo.empty();
    }
  }

  /// Clear cached info to force re-collection.
  void clearCache() {
    _cachedInfo = null;
  }
}

/// Structured APK metadata.
class ApkInfo {
  final String packageName;
  final String versionName;
  final int versionCode;
  final String apkHash;
  final int apkSize;
  final String certFingerprint;
  final List<String> permissions;
  final int permissionsCount;
  final List<String> sensitivePermissions;
  final int sensitivePermissionsCount;
  final List<String> activities;
  final List<String> services;
  final List<String> receivers;
  final List<String> providers;
  final String installer;
  final bool isDebuggable;
  final int firstInstallTime;
  final int lastUpdateTime;
  final bool isValid;

  const ApkInfo({
    this.packageName = '',
    this.versionName = '',
    this.versionCode = 0,
    this.apkHash = '',
    this.apkSize = 0,
    this.certFingerprint = '',
    this.permissions = const [],
    this.permissionsCount = 0,
    this.sensitivePermissions = const [],
    this.sensitivePermissionsCount = 0,
    this.activities = const [],
    this.services = const [],
    this.receivers = const [],
    this.providers = const [],
    this.installer = 'unknown',
    this.isDebuggable = false,
    this.firstInstallTime = 0,
    this.lastUpdateTime = 0,
    this.isValid = true,
  });

  factory ApkInfo.empty() => const ApkInfo(isValid: false);

  factory ApkInfo.fromJson(Map<String, dynamic> json) {
    return ApkInfo(
      packageName: json['package_name'] as String? ?? '',
      versionName: json['version_name'] as String? ?? '',
      versionCode: (json['version_code'] as num?)?.toInt() ?? 0,
      apkHash: json['apk_hash'] as String? ?? '',
      apkSize: (json['apk_size'] as num?)?.toInt() ?? 0,
      certFingerprint: json['cert_fingerprint'] as String? ?? '',
      permissions:
          (json['permissions'] as List?)?.map((e) => e.toString()).toList() ??
              [],
      permissionsCount: (json['permissions_count'] as num?)?.toInt() ?? 0,
      sensitivePermissions: (json['sensitive_permissions'] as List?)
              ?.map((e) => e.toString())
              .toList() ??
          [],
      sensitivePermissionsCount:
          (json['sensitive_permissions_count'] as num?)?.toInt() ?? 0,
      activities:
          (json['activities'] as List?)?.map((e) => e.toString()).toList() ??
              [],
      services:
          (json['services'] as List?)?.map((e) => e.toString()).toList() ?? [],
      receivers:
          (json['receivers'] as List?)?.map((e) => e.toString()).toList() ?? [],
      providers:
          (json['providers'] as List?)?.map((e) => e.toString()).toList() ?? [],
      installer: json['installer'] as String? ?? 'unknown',
      isDebuggable: json['is_debuggable'] as bool? ?? false,
      firstInstallTime: (json['first_install_time'] as num?)?.toInt() ?? 0,
      lastUpdateTime: (json['last_update_time'] as num?)?.toInt() ?? 0,
      isValid: json['error'] == null,
    );
  }

  /// Whether this APK was sideloaded (not from Play Store).
  bool get isSideloaded =>
      installer == 'unknown (sideloaded)' ||
      installer == 'unknown' ||
      installer == 'external_file';

  /// Human-readable APK size.
  String get formattedSize {
    if (apkSize < 1024) return '$apkSize B';
    if (apkSize < 1024 * 1024)
      return '${(apkSize / 1024).toStringAsFixed(1)} KB';
    return '${(apkSize / (1024 * 1024)).toStringAsFixed(1)} MB';
  }

  /// Short hash for display.
  String get shortHash =>
      apkHash.length > 16 ? '${apkHash.substring(0, 16)}...' : apkHash;

  /// Short cert fingerprint for display.
  String get shortCertFingerprint => certFingerprint.length > 16
      ? '${certFingerprint.substring(0, 16)}...'
      : certFingerprint;
}
