import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:device_info_plus/device_info_plus.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:logger/logger.dart';

import 'models/security_report.dart';
import 'secure_http_client.dart';

/// Service responsible for communicating security reports to the backend.
///
/// Handles device identification, report serialization, authentication,
/// and force_logout responses.
class SecurityService {
  final SecureHttpClient _httpClient = SecureHttpClient();
  final FlutterSecureStorage _secureStorage = const FlutterSecureStorage();
  final DeviceInfoPlugin _deviceInfo = DeviceInfoPlugin();
  final _log = Logger(printer: PrettyPrinter(methodCount: 0));

  String? _deviceId;
  String? _authToken;

  /// Initialize the service — loads stored auth token and device ID.
  Future<void> initialize() async {
    // Load cached device ID
    _deviceId = await _secureStorage.read(key: 'device_id');

    // Load stored JWT token
    _authToken = await _secureStorage.read(key: 'auth_token');
    if (_authToken != null) {
      _httpClient.setAuthToken(_authToken!);
    }

    // Load custom backend URL if configured
    final backendUrl = await _secureStorage.read(key: 'backend_url');
    if (backendUrl != null) {
      _httpClient.setBaseUrl(backendUrl);
    }
  }

  /// Get or generate a unique device identifier.
  Future<String> getDeviceId() async {
    if (_deviceId != null) return _deviceId!;

    try {
      final androidInfo = await _deviceInfo.androidInfo;
      // Create a stable fingerprint from device properties
      final raw =
          '${androidInfo.id}-${androidInfo.model}-${androidInfo.fingerprint}';
      _deviceId = sha256.convert(utf8.encode(raw)).toString().substring(0, 32);
    } catch (_) {
      // Fallback for non-Android platforms
      final raw = 'device-${DateTime.now().millisecondsSinceEpoch}';
      _deviceId = sha256.convert(utf8.encode(raw)).toString().substring(0, 32);
    }

    await _secureStorage.write(key: 'device_id', value: _deviceId);
    return _deviceId!;
  }

  /// Send a security report to the backend.
  ///
  /// Returns [SecurityReportResponse] on success, null on failure.
  /// The system continues in offline mode if the backend is unreachable.
  Future<SecurityReportResponse?> sendReport(SecurityReport report,
      {bool waitForLlm = false}) async {
    final response = await _httpClient.post(
      '/api/security/report${waitForLlm ? '?wait_for_llm=true' : ''}',
      report.toJson(),
    );

    if (response == null) {
      _log.w('Report send failed — operating in offline mode');
      return null;
    }

    final parsed = SecurityReportResponse.fromJson(response);

    if (parsed.isForceLogout) {
      _log.e('FORCE LOGOUT: revoking local credentials');
      await _revokeLocalCredentials();
    }

    return parsed;
  }

  /// Send an external APK audit to the backend for analysis.
  Future<SecurityReportResponse?> sendExternalApkAnalysis(
      ApkAudit audit) async {
    final response = await _httpClient.post(
      '/api/security/apk-analysis',
      audit.toJson(),
    );

    if (response == null) {
      _log.w('Cloud analysis failed — backend unreachable');
      return null;
    }

    return SecurityReportResponse.fromJson(response);
  }

  /// Check if Ollama/Qwen is reachable and return model info.
  ///
  /// Returns a map with 'reachable' (bool) and 'model' (String?) keys.
  Future<Map<String, dynamic>> checkOllamaStatus() async {
    try {
      final response = await _httpClient.get('/api/security/health');
      if (response != null) {
        return {
          'reachable': true,
          'model': response['llm_model'] ?? 'qwen2.5:1.5b',
          'status': response['llm_status'] ?? 'unknown',
        };
      }
    } catch (e) {
      _log.w('Ollama status check failed: $e');
    }
    return {
      'reachable': false,
      'model': null,
      'status': 'unreachable',
    };
  }

  /// Authenticate with the backend to obtain a JWT token.
  Future<bool> authenticate(String apiKey) async {
    final response = await _httpClient.post('/api/auth/token', {
      'api_key': apiKey,
      'device_id': await getDeviceId(),
    });

    if (response != null && response.containsKey('access_token')) {
      _authToken = response['access_token'] as String;
      _httpClient.setAuthToken(_authToken!);
      await _secureStorage.write(key: 'auth_token', value: _authToken);
      _log.i('Authentication successful');
      return true;
    }

    _log.e('Authentication failed');
    return false;
  }

  /// Configure the backend URL.
  Future<void> setBackendUrl(String url) async {
    _httpClient.setBaseUrl(url);
    await _secureStorage.write(key: 'backend_url', value: url);
  }

  /// Explain risk for a single APK item (permission, activity, service, etc.)
  ///
  /// Returns a map with 'explanation', 'risk_level', 'recommendation'.
  Future<Map<String, dynamic>?> explainRisk({
    required String itemType,
    required String itemName,
    required Map<String, dynamic> context,
  }) async {
    final response = await _httpClient.post(
      '/api/security/explain-risk',
      {
        'item_type': itemType,
        'item_name': itemName,
        'context': context,
      },
    );

    if (response == null) {
      _log.w('Explain risk failed — backend unreachable');
      return null;
    }

    return response;
  }

  /// Revoke all local credentials on force logout.
  Future<void> _revokeLocalCredentials() async {
    _authToken = null;
    _httpClient.clearAuthToken();
    await _secureStorage.delete(key: 'auth_token');
  }

  void dispose() {
    _httpClient.dispose();
  }
}
