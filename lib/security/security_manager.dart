import 'dart:async';

import 'package:logger/logger.dart';

import 'apk_info_collector.dart';
import 'models/behavior_event.dart';
import 'models/security_report.dart';
import 'models/threat_level.dart';
import 'native_bridge.dart';
import 'security_service.dart';
import 'tflite_analyzer.dart';

/// Singleton orchestrator for the entire mobile security detection system.
///
/// Coordinates native checks, TFLite inference, event buffering,
/// and backend reporting. Implements the offline-first detection pipeline
/// as described in the architecture spec.
class SecurityManager {
  // ── Singleton ──
  static final SecurityManager _instance = SecurityManager._internal();
  factory SecurityManager() => _instance;
  SecurityManager._internal();

  // ── Dependencies ──
  final NativeSecurityBridge _nativeBridge = NativeSecurityBridge();
  final ApkInfoCollector _apkCollector = ApkInfoCollector();
  final TFLiteAnalyzer _tfliteAnalyzer = TFLiteAnalyzer();
  final SecurityService _securityService = SecurityService();
  final _log = Logger(printer: PrettyPrinter(methodCount: 0));

  // ── State ──
  final List<BehaviorEvent> _eventBuffer = [];
  static const int _maxBufferSize = 50;
  Timer? _periodicCheckTimer;
  Timer? _simulationTimer;
  bool _isInitialized = false;

  ThreatLevel _currentThreatLevel = ThreatLevel.clean;
  SecurityChecks? _lastSecurityChecks;
  ApkAudit? _lastApkAudit;
  double _lastAnomalyScore = 0.0;

  // ── Callbacks ──
  void Function(ThreatLevel level)? onThreatLevelChanged;
  void Function(SecurityReportResponse response)? onForceLogout;

  // ── Accessors ──
  ThreatLevel get currentThreatLevel => _currentThreatLevel;
  SecurityChecks? get lastSecurityChecks => _lastSecurityChecks;
  ApkAudit? get lastApkAudit => _lastApkAudit;
  double get lastAnomalyScore => _lastAnomalyScore;
  bool get isInitialized => _isInitialized;
  int get eventBufferSize => _eventBuffer.length;

  /// Initialize the entire security system.
  ///
  /// Must be called once at app startup, before any other operations.
  Future<void> initialize() async {
    if (_isInitialized) return;

    _log.i('Initializing SecurityManager...');

    // 1. Initialize TFLite model
    await _tfliteAnalyzer.initialize();

    // 2. Initialize secure HTTP client for backend reporting
    await _securityService.initialize();

    // 3. Run initial security checks immediately
    await runFullSecurityScan();

    _isInitialized = true;
    _log.i(
      'SecurityManager initialized — threat level: ${_currentThreatLevel.label}',
    );
  }

  /// Run the complete security scan pipeline.
  ///
  /// 1. Native checks (Frida, root, signature, DEX, etc.)
  /// 2. TFLite behavioral analysis
  /// 3. Combined threat level assessment
  /// 4. Backend reporting (if connected)
  Future<ThreatLevel> runFullSecurityScan() async {
    _log.d('Running full security scan...');

    // Step 1: Native security checks
    final checks = await _nativeBridge.runAllChecks();
    _lastSecurityChecks = checks;

    // Step 2: APK Integrity Analysis
    final apkInfo = await _apkCollector.collectApkInfo();
    final apkAudit = _analyzeApk(apkInfo);
    _lastApkAudit = apkAudit;

    // Step 3: TFLite behavioral analysis
    final features = _tfliteAnalyzer.extractFeatures(_eventBuffer);
    _lastAnomalyScore = await _tfliteAnalyzer.analyzeBuffer(_eventBuffer);

    // Step 4: Determine local threat level
    final staticScore = _calculateStaticScore(checks, apkAudit);
    final combinedScore = (staticScore * 0.6) + (_lastAnomalyScore * 0.4);
    final threatLevel = ThreatLevel.fromScore(combinedScore);

    // Step 5: Update state and notify
    if (threatLevel != _currentThreatLevel) {
      _currentThreatLevel = threatLevel;
      onThreatLevelChanged?.call(threatLevel);
      _log.w(
        'Threat level changed to: ${threatLevel.label} (score: ${combinedScore.toStringAsFixed(3)})',
      );
    }

    // Update anomaly score immediately for UI
    onThreatLevelChanged?.call(threatLevel);

    // Step 6: Report to backend
    try {
      final report = SecurityReport(
        deviceId: await _securityService.getDeviceId(),
        securityChecks: checks,
        apkAudit: apkAudit,
        behaviorFeatures: features,
        localAnomalyScore: _lastAnomalyScore,
        localThreatLevel: threatLevel,
      );

      final response = await _securityService.sendReport(report);
      if (response != null && response.isForceLogout) {
        _log.e('FORCE LOGOUT ordered by backend');
        onForceLogout?.call(response);
      }
    } catch (e) {
      _log.w('Backend report failed (offline mode): $e');
      // Offline-first: local detection continues without backend
    }

    return threatLevel;
  }

  /// Delegate external APK analysis to the securty service.
  Future<SecurityReportResponse?> sendExternalApkAnalysis(
      ApkAudit audit) async {
    return _securityService.sendExternalApkAnalysis(audit);
  }

  /// Send the currently installed (self) APK for cloud AI analysis.
  Future<SecurityReportResponse?> sendSelfApkAnalysis() async {
    if (_lastApkAudit == null) return null;
    return _securityService.sendExternalApkAnalysis(_lastApkAudit!);
  }

  /// Check if Ollama/Qwen is reachable.
  Future<Map<String, dynamic>> checkOllamaStatus() async {
    return _securityService.checkOllamaStatus();
  }

  /// Analyze raw APK info and generate a structured audit.
  ApkAudit _analyzeApk(ApkInfo info) {
    return ApkAudit(
      packageName: info.packageName,
      version: '${info.versionName} (${info.versionCode})',
      apkHash: info.apkHash,
      installerSource: info.installer,
      isSideloaded: info.isSideloaded,
      isDebuggable: info.isDebuggable,
      sensitivePermissionsCount: info.sensitivePermissionsCount,
      permissions: info.permissions,
      sensitivePermissions: info.sensitivePermissions,
      activities: info.activities,
      services: info.services,
      receivers: info.receivers,
      providers: info.providers,
      isValid: info.isValid,
    );
  }

  /// Record a behavioral event for the TFLite anomaly detector.
  void recordEvent(BehaviorEvent event) {
    _eventBuffer.add(event);

    // Sliding window: keep the last N events
    while (_eventBuffer.length > _maxBufferSize) {
      _eventBuffer.removeAt(0);
    }
  }

  // ── Convenience event recorders ──

  void recordNetworkCall({String? endpoint, int? statusCode}) {
    recordEvent(
      BehaviorEvent(
        type: BehaviorEventType.networkCall,
        metadata: {'endpoint': endpoint, 'status_code': statusCode},
      ),
    );
  }

  void recordFileAccess({String? path, String? operation}) {
    recordEvent(
      BehaviorEvent(
        type: BehaviorEventType.fileAccess,
        metadata: {'path': path, 'operation': operation},
      ),
    );
  }

  void recordApiCall({required String endpoint}) {
    recordEvent(
      BehaviorEvent(
        type: BehaviorEventType.apiCall,
        metadata: {'endpoint': endpoint},
      ),
    );
  }

  void recordCpuSpike({double? usage}) {
    recordEvent(
      BehaviorEvent(
        type: BehaviorEventType.cpuSpike,
        metadata: {'usage': usage},
      ),
    );
  }

  void recordMemoryAnomaly({required double score}) {
    recordEvent(
      BehaviorEvent(
        type: BehaviorEventType.memoryAnomaly,
        metadata: {'score': score},
      ),
    );
  }

  /// Calculate static threat score from native security checks.
  ///
  /// Uses calibrated weights for native checks + APK attributes.
  double _calculateStaticScore(SecurityChecks checks, ApkAudit audit) {
    double maxScore = 0.0;

    // --- APK Integrity ---
    if (!audit.isValid) {
      maxScore = 0.85; // Failed to parse APK info
    }
    if (audit.isSideloaded) {
      // Sideloading is common but risky
      maxScore = maxScore > 0.45 ? maxScore : 0.45;
    }
    if (audit.isDebuggable) {
      // Debuggable logic in prod is VERY dangerous
      maxScore = maxScore > 0.90 ? maxScore : 0.90;
    }

    // --- Native Checks ---
    if (checks.fridaDetected) {
      maxScore = maxScore > 0.95 ? maxScore : 0.95;
    }
    if (checks.hookDetected) {
      maxScore = maxScore > 0.90 ? maxScore : 0.90;
    }
    if (checks.certPinningBypassed) {
      maxScore = maxScore > 0.85 ? maxScore : 0.85;
    }
    if (!checks.signatureValid) {
      maxScore = maxScore > 0.80 ? maxScore : 0.80;
    }
    if (!checks.dexIntegrityValid) {
      maxScore = maxScore > 0.80 ? maxScore : 0.80;
    }
    if (checks.xposedDetected) {
      maxScore = maxScore > 0.70 ? maxScore : 0.70;
    }
    if (checks.debuggerAttached) {
      maxScore = maxScore > 0.60 ? maxScore : 0.60;
    }
    if (checks.rootDetected) {
      maxScore = maxScore > 0.40 ? maxScore : 0.40;
    }
    if (checks.emulatorDetected) {
      maxScore = maxScore > 0.20 ? maxScore : 0.20;
    }

    return maxScore;
  }

  /// Clean up resources.
  void dispose() {
    _periodicCheckTimer?.cancel();
    _simulationTimer?.cancel();
    _tfliteAnalyzer.dispose();
    _eventBuffer.clear();
    _isInitialized = false;
  }
}
