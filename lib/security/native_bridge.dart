import 'package:flutter/services.dart';
import 'package:logger/logger.dart';
import 'models/security_report.dart';

/// Bridge to native Kotlin/Swift security detectors via Method Channel.
///
/// Each detection vector runs independently so that a hook on one
/// cannot disable the others.
class NativeSecurityBridge {
  static const _channel = MethodChannel('com.example.security/native');
  final _log = Logger(printer: PrettyPrinter(methodCount: 0));

  /// Run all native security checks and return aggregated results.
  Future<SecurityChecks> runAllChecks() async {
    try {
      final result = await _channel.invokeMethod<Map>('runAllChecks');
      if (result == null) {
        _log.w('Native bridge returned null — defaulting to safe state');
        return const SecurityChecks();
      }
      return SecurityChecks.fromJson(Map<String, dynamic>.from(result));
    } on PlatformException catch (e) {
      _log.e('Native security check failed: ${e.message}');
      // If native checks fail, assume compromised environment
      return const SecurityChecks(fridaDetected: true, hookDetected: true);
    } on MissingPluginException {
      _log.w(
        'Native security plugin not registered — running on unsupported platform',
      );
      return const SecurityChecks();
    }
  }

  /// Run a single check by name. Used for targeted re-verification.
  Future<bool> runSingleCheck(String checkName) async {
    try {
      final result = await _channel.invokeMethod<bool>('runCheck', {
        'check': checkName,
      });
      return result ?? false;
    } on PlatformException catch (e) {
      _log.e('Single check "$checkName" failed: ${e.message}');
      return true; // Assume compromised on failure
    }
  }

  /// Get additional environment metadata from native layer.
  Future<Map<String, dynamic>> getEnvironmentInfo() async {
    try {
      final result = await _channel.invokeMethod<Map>('getEnvironmentInfo');
      return result != null ? Map<String, dynamic>.from(result) : {};
    } catch (e) {
      _log.e('Failed to get environment info: $e');
      return {};
    }
  }
}
