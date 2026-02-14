import 'threat_level.dart';

/// Results from all native security checks.
class SecurityChecks {
  final bool fridaDetected;
  final bool rootDetected;
  final bool signatureValid;
  final bool dexIntegrityValid;
  final bool xposedDetected;
  final bool debuggerAttached;
  final bool emulatorDetected;
  final bool hookDetected;
  final bool certPinningBypassed;

  const SecurityChecks({
    this.fridaDetected = false,
    this.rootDetected = false,
    this.signatureValid = true,
    this.dexIntegrityValid = true,
    this.xposedDetected = false,
    this.debuggerAttached = false,
    this.emulatorDetected = false,
    this.hookDetected = false,
    this.certPinningBypassed = false,
  });

  /// Returns true if any critical check failed.
  bool get hasCriticalIssue =>
      fridaDetected || hookDetected || certPinningBypassed;

  /// Returns true if any check failed.
  bool get hasAnyIssue =>
      fridaDetected ||
      rootDetected ||
      !signatureValid ||
      !dexIntegrityValid ||
      xposedDetected ||
      debuggerAttached ||
      emulatorDetected ||
      hookDetected ||
      certPinningBypassed;

  Map<String, dynamic> toJson() => {
        'frida_detected': fridaDetected,
        'root_detected': rootDetected,
        'signature_valid': signatureValid,
        'dex_integrity_valid': dexIntegrityValid,
        'xposed_detected': xposedDetected,
        'debugger_attached': debuggerAttached,
        'emulator_detected': emulatorDetected,
        'hook_detected': hookDetected,
        'cert_pinning_bypassed': certPinningBypassed,
      };

  factory SecurityChecks.fromJson(Map<String, dynamic> json) {
    return SecurityChecks(
      fridaDetected: json['frida_detected'] ?? false,
      rootDetected: json['root_detected'] ?? false,
      signatureValid: json['signature_valid'] ?? true,
      dexIntegrityValid: json['dex_integrity_valid'] ?? true,
      xposedDetected: json['xposed_detected'] ?? false,
      debuggerAttached: json['debugger_attached'] ?? false,
      emulatorDetected: json['emulator_detected'] ?? false,
      hookDetected: json['hook_detected'] ?? false,
      certPinningBypassed: json['cert_pinning_bypassed'] ?? false,
    );
  }
}

/// Behavioral features extracted from event buffer (6 dimensions).
class BehaviorFeatures {
  final double networkCallsCount;
  final double fileAccessCount;
  final double timingEntropy;
  final double apiCallSequenceHash;
  final double memoryAnomalyScore;
  final double cpuSpikeCount;

  const BehaviorFeatures({
    this.networkCallsCount = 0,
    this.fileAccessCount = 0,
    this.timingEntropy = 0.5,
    this.apiCallSequenceHash = 0,
    this.memoryAnomalyScore = 0,
    this.cpuSpikeCount = 0,
  });

  /// Convert to a flat list for TFLite model input.
  List<double> toFeatureVector() => [
        networkCallsCount,
        fileAccessCount,
        timingEntropy,
        apiCallSequenceHash,
        memoryAnomalyScore,
        cpuSpikeCount,
      ];

  Map<String, dynamic> toJson() => {
        'network_calls_count': networkCallsCount,
        'file_access_count': fileAccessCount,
        'timing_entropy': timingEntropy,
        'api_call_sequence_hash': apiCallSequenceHash,
        'memory_anomaly_score': memoryAnomalyScore,
        'cpu_spike_count': cpuSpikeCount,
      };

  factory BehaviorFeatures.fromJson(Map<String, dynamic> json) {
    return BehaviorFeatures(
      networkCallsCount: (json['network_calls_count'] ?? 0).toDouble(),
      fileAccessCount: (json['file_access_count'] ?? 0).toDouble(),
      timingEntropy: (json['timing_entropy'] ?? 0.5).toDouble(),
      apiCallSequenceHash: (json['api_call_sequence_hash'] ?? 0).toDouble(),
      memoryAnomalyScore: (json['memory_anomaly_score'] ?? 0).toDouble(),
      cpuSpikeCount: (json['cpu_spike_count'] ?? 0).toDouble(),
    );
  }
}

/// Complete security report sent to the backend.
class SecurityReport {
  final String deviceId;
  final String? appVersion;
  final String? platform;
  final String? osVersion;
  final SecurityChecks securityChecks;
  final ApkAudit? apkAudit;
  final BehaviorFeatures behaviorFeatures;
  final double? localAnomalyScore;
  final ThreatLevel? localThreatLevel;
  final DateTime timestamp;

  SecurityReport({
    required this.deviceId,
    this.appVersion,
    this.platform,
    this.osVersion,
    required this.securityChecks,
    this.apkAudit,
    required this.behaviorFeatures,
    this.localAnomalyScore,
    this.localThreatLevel,
    DateTime? timestamp,
  }) : timestamp = timestamp ?? DateTime.now();

  Map<String, dynamic> toJson() => {
        'device_id': deviceId,
        'app_version': appVersion,
        'platform': platform,
        'os_version': osVersion,
        'security_checks': securityChecks.toJson(),
        'apk_audit': apkAudit?.toJson(),
        'behavior_features': behaviorFeatures.toJson(),
        'local_anomaly_score': localAnomalyScore,
        'local_threat_level': localThreatLevel?.name,
        'timestamp': timestamp.toIso8601String(),
      };
}

/// Audit result for the APK integrity.
class ApkAudit {
  final String packageName;
  final String version;
  final String apkHash;
  final String installerSource;
  final bool isSideloaded;
  final bool isDebuggable;
  final int sensitivePermissionsCount;
  final List<String> permissions;
  final List<String> sensitivePermissions;
  final List<String> activities;
  final List<String> services;
  final List<String> receivers;
  final List<String> providers;
  final bool isValid;

  const ApkAudit({
    required this.packageName,
    required this.version,
    required this.apkHash,
    required this.installerSource,
    required this.isSideloaded,
    required this.isDebuggable,
    required this.sensitivePermissionsCount,
    this.permissions = const [],
    this.sensitivePermissions = const [],
    this.activities = const [],
    this.services = const [],
    this.receivers = const [],
    this.providers = const [],
    required this.isValid,
  });

  Map<String, dynamic> toJson() => {
        'package_name': packageName,
        'version': version,
        'apk_hash': apkHash,
        'installer_source': installerSource,
        'is_sideloaded': isSideloaded,
        'is_debuggable': isDebuggable,
        'sensitive_permissions_count': sensitivePermissionsCount,
        'sensitive_permissions': sensitivePermissions,
        'permissions': permissions,
        'activities': activities,
        'services': services,
        'receivers': receivers,
        'providers': providers,
        'is_valid': isValid,
      };
}

/// Response from the backend after processing a security report.
class SecurityReportResponse {
  final ThreatLevel threatLevel;
  final double score;
  final String? action;
  final String? message;
  final String? llmAnalysis;

  const SecurityReportResponse({
    required this.threatLevel,
    required this.score,
    this.action,
    this.message,
    this.llmAnalysis,
  });

  /// Whether the backend ordered a force logout.
  bool get isForceLogout => action == 'force_logout';

  factory SecurityReportResponse.fromJson(Map<String, dynamic> json) {
    return SecurityReportResponse(
      threatLevel: ThreatLevel.fromString(json['threat_level'] ?? 'clean'),
      score: (json['score'] ?? 0).toDouble(),
      action: json['action'],
      message: json['message'],
      llmAnalysis: json['llm_analysis'],
    );
  }
}
