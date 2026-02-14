import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:logger/logger.dart';

import 'apk_info_collector.dart';
import 'models/security_report.dart';

/// Result from scanning an external APK — audit data + optional cloud response.
class ExternalApkScanResult {
  final ApkAudit audit;
  final SecurityReportResponse? cloudResponse;

  const ExternalApkScanResult({
    required this.audit,
    this.cloudResponse,
  });
}

/// Service to handle selecting and scanning external APK files.
class ExternalApkScanner {
  final _apkCollector = ApkInfoCollector();
  final _log = Logger(printer: PrettyPrinter(methodCount: 0));

  /// Open file picker to select an APK and return a local audit.
  ///
  /// Returns [ApkAudit] from local static analysis only.
  /// Cloud analysis is handled separately by the caller.
  Future<ApkAudit?> pickAndAnalyzeApk() async {
    try {
      final result = await FilePicker.platform.pickFiles(
        type: FileType.custom,
        allowedExtensions: ['apk'],
      );

      if (result == null || result.files.isEmpty) {
        _log.i('Aucun fichier sélectionné');
        return null;
      }

      final path = result.files.single.path;
      if (path == null) {
        _log.w('Le fichier sélectionné n\'a pas de chemin');
        return null;
      }

      _log.d('Analyse APK externe : $path');
      final info = await _apkCollector.getExternalApkInfo(path);

      return _analyzeExternalApk(info, path);
    } catch (e) {
      _log.e('Échec de l\'analyse APK externe : $e');
      return null;
    }
  }

  ApkAudit _analyzeExternalApk(ApkInfo info, String path) {
    final file = File(path);
    final size = file.existsSync() ? file.lengthSync() : 0;

    return ApkAudit(
      packageName: info.packageName,
      version: '${info.versionName} (${info.versionCode})',
      apkHash: info.apkHash,
      installerSource: 'Fichier Externe',
      isSideloaded: true,
      isDebuggable: info.isDebuggable,
      sensitivePermissionsCount: info.sensitivePermissionsCount,
      permissions: info.permissions,
      sensitivePermissions: info.sensitivePermissions,
      activities: info.activities,
      services: info.services,
      receivers: info.receivers,
      providers: info.providers,
      isValid: info.isValid && info.packageName.isNotEmpty,
    );
  }
}
