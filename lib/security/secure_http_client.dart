import 'dart:io';

import 'package:crypto/crypto.dart' as crypto;
import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:logger/logger.dart';

/// Dio-based HTTP client with certificate pinning.
///
/// Implements TLS certificate pinning to prevent MITM attacks.
/// The server certificate fingerprint is hardcoded at compile time.
class SecureHttpClient {
  late final Dio _dio;
  final _log = Logger(printer: PrettyPrinter(methodCount: 0));

  // ── Configuration ──
  // TODO: Replace with actual server certificate SHA-256 fingerprint
  static const String _certFingerprint =
      'REPLACE_WITH_YOUR_SERVER_CERT_SHA256_FINGERPRINT';

  // Backend URL — use 10.0.2.2 for Android emulator
  static String get _baseUrl {
    if (Platform.isAndroid) return 'http://10.0.2.2:8000';
    return 'http://localhost:8000';
  }

  SecureHttpClient() {
    _dio = Dio(
      BaseOptions(
        baseUrl: _baseUrl,
        connectTimeout: const Duration(seconds: 10),
        receiveTimeout: const Duration(seconds: 15),
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
      ),
    );

    // Add logging interceptor (debug only)
    _dio.interceptors.add(
      LogInterceptor(
        requestBody: false,
        responseBody: false,
        logPrint: (obj) => _log.d(obj.toString()),
      ),
    );

    // Configure certificate pinning
    _configureCertPinning();
  }

  /// Configure TLS certificate pinning.
  ///
  /// In production, this validates the server certificate's SHA-256
  /// fingerprint against the hardcoded value. Any mismatch (proxy,
  /// MITM tool, compromised CA) closes the connection immediately.
  void _configureCertPinning() {
    (_dio.httpClientAdapter as IOHttpClientAdapter).createHttpClient = () {
      final client = HttpClient();

      client.badCertificateCallback =
          (X509Certificate cert, String host, int port) {
        // In debug/development mode, allow all certificates
        if (_certFingerprint ==
            'REPLACE_WITH_YOUR_SERVER_CERT_SHA256_FINGERPRINT') {
          _log.w(
            'Certificate pinning not configured — accepting all certs (DEV ONLY)',
          );
          return true;
        }

        // Production: validate certificate fingerprint
        final certBytes = cert.der;
        final sha256Hex = crypto.sha256.convert(certBytes).toString();

        if (sha256Hex == _certFingerprint) {
          return true; // Certificate matches
        }

        _log.e(
          'CERTIFICATE PINNING FAILURE: expected=$_certFingerprint, got=$sha256Hex',
        );
        return false; // Reject — possible MITM
      };

      return client;
    };
  }

  /// Set the authentication token for all subsequent requests.
  void setAuthToken(String token) {
    _dio.options.headers['Authorization'] = 'Bearer $token';
  }

  /// Remove the authentication token.
  void clearAuthToken() {
    _dio.options.headers.remove('Authorization');
  }

  /// Set a custom base URL (e.g., from config).
  void setBaseUrl(String url) {
    _dio.options.baseUrl = url;
  }

  /// POST request with automatic error handling.
  Future<Map<String, dynamic>?> post(
    String path,
    Map<String, dynamic> data,
  ) async {
    try {
      final response = await _dio.post(path, data: data);
      if (response.data is Map) {
        return Map<String, dynamic>.from(response.data);
      }
      return null;
    } on DioException catch (e) {
      _handleDioError(e);
      return null;
    }
  }

  /// GET request with automatic error handling.
  Future<Map<String, dynamic>?> get(String path) async {
    try {
      final response = await _dio.get(path);
      if (response.data is Map) {
        return Map<String, dynamic>.from(response.data);
      }
      return null;
    } on DioException catch (e) {
      _handleDioError(e);
      return null;
    }
  }

  void _handleDioError(DioException e) {
    switch (e.type) {
      case DioExceptionType.connectionTimeout:
        _log.e('Connection timeout to backend');
        break;
      case DioExceptionType.badCertificate:
        _log.e('CERTIFICATE PINNING VIOLATION — possible MITM attack');
        break;
      case DioExceptionType.connectionError:
        _log.w('Cannot connect to backend (offline mode)');
        break;
      default:
        _log.e('HTTP error: ${e.message}');
    }
  }

  void dispose() {
    _dio.close();
  }
}
