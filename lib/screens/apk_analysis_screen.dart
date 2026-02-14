import 'dart:async';

import 'package:animate_do/animate_do.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';

import '../app_theme.dart';
import '../security/apk_info_collector.dart';
import '../security/models/threat_level.dart';
import '../security/security_manager.dart';

/// Screen that displays a complete analysis of the installed APK.
///
/// Shows:
/// - APK integrity (hash, signature, DEX verification)
/// - Security classification (Sain / Suspect / Compromis)
/// - Permissions analysis (total + sensitive)
/// - Package metadata
/// - Native security check results
class ApkAnalysisScreen extends StatefulWidget {
  const ApkAnalysisScreen({super.key});

  @override
  State<ApkAnalysisScreen> createState() => _ApkAnalysisScreenState();
}

class _ApkAnalysisScreenState extends State<ApkAnalysisScreen>
    with SingleTickerProviderStateMixin {
  final ApkInfoCollector _apkCollector = ApkInfoCollector();
  final SecurityManager _securityManager = SecurityManager();

  late AnimationController _pulseController;

  ApkInfo? _apkInfo;
  bool _isLoading = true;
  bool _isRescanning = false;

  @override
  void initState() {
    super.initState();
    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat(reverse: true);
    _loadApkInfo();
  }

  @override
  void dispose() {
    _pulseController.dispose();
    super.dispose();
  }

  Future<void> _loadApkInfo() async {
    final info = await _apkCollector.collectApkInfo();
    if (mounted) {
      setState(() {
        _apkInfo = info;
        _isLoading = false;
      });
    }
  }

  Future<void> _rescan() async {
    setState(() => _isRescanning = true);
    _apkCollector.clearCache();
    await _securityManager.runFullSecurityScan();
    await _loadApkInfo();
    if (mounted) setState(() => _isRescanning = false);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      appBar: AppBar(
        backgroundColor: AppTheme.bgDark,
        elevation: 0,
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(6),
              decoration: BoxDecoration(
                gradient: AppTheme.primaryGradient,
                borderRadius: BorderRadius.circular(10),
              ),
              child:
                  const Icon(Icons.find_in_page, color: Colors.white, size: 20),
            ),
            const SizedBox(width: 10),
            Text(
              'APK Analysis',
              style: GoogleFonts.inter(
                fontWeight: FontWeight.w700,
                fontSize: 18,
                color: AppTheme.textPrimary,
              ),
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: _isRescanning
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(
                      strokeWidth: 2,
                      color: AppTheme.accentCyan,
                    ),
                  )
                : const Icon(Icons.refresh, color: AppTheme.textSecondary),
            onPressed: _isRescanning ? null : _rescan,
            tooltip: 'Re-analyze',
          ),
          const SizedBox(width: 8),
        ],
      ),
      body: _isLoading
          ? const Center(
              child: CircularProgressIndicator(color: AppTheme.accentCyan),
            )
          : _buildContent(),
    );
  }

  Widget _buildContent() {
    final info = _apkInfo;
    if (info == null || !info.isValid) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.error_outline,
                color: AppTheme.accentRed, size: 48),
            const SizedBox(height: 16),
            Text(
              'Unable to collect APK information',
              style: GoogleFonts.inter(color: AppTheme.textSecondary),
            ),
          ],
        ),
      );
    }

    final threat = _securityManager.currentThreatLevel;
    final checks = _securityManager.lastSecurityChecks;
    final score = _securityManager.lastAnomalyScore;

    return SingleChildScrollView(
      physics: const BouncingScrollPhysics(),
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── Classification card ──
          FadeInDown(
            duration: const Duration(milliseconds: 400),
            child: _buildClassificationCard(threat, score),
          ),
          const SizedBox(height: 16),

          // ── APK Integrity card ──
          FadeInUp(
            delay: const Duration(milliseconds: 100),
            duration: const Duration(milliseconds: 400),
            child: _buildIntegrityCard(info, checks),
          ),
          const SizedBox(height: 16),

          // ── Permissions card ──
          FadeInUp(
            delay: const Duration(milliseconds: 200),
            duration: const Duration(milliseconds: 400),
            child: _buildPermissionsCard(info),
          ),
          const SizedBox(height: 16),

          // ── Security Checks card ──
          FadeInUp(
            delay: const Duration(milliseconds: 300),
            duration: const Duration(milliseconds: 400),
            child: _buildSecurityChecksCard(checks),
          ),
          const SizedBox(height: 16),

          // ── Package Metadata card ──
          FadeInUp(
            delay: const Duration(milliseconds: 400),
            duration: const Duration(milliseconds: 400),
            child: _buildMetadataCard(info),
          ),
          const SizedBox(height: 32),
        ],
      ),
    );
  }

  Widget _buildClassificationCard(ThreatLevel threat, double score) {
    final color = AppTheme.threatColor(threat.name);
    final classification = _getClassification(threat);

    return AnimatedBuilder(
      animation: _pulseController,
      builder: (context, child) {
        return Container(
          width: double.infinity,
          padding: const EdgeInsets.all(24),
          decoration: BoxDecoration(
            color: AppTheme.bgCard,
            borderRadius: BorderRadius.circular(20),
            border: Border.all(color: color.withOpacity(0.4), width: 1.5),
            boxShadow: [
              BoxShadow(
                color: color.withOpacity(0.05 + _pulseController.value * 0.08),
                blurRadius: 25,
                spreadRadius: 2,
              ),
            ],
          ),
          child: Column(
            children: [
              // Classification badge
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
                decoration: BoxDecoration(
                  color: color.withOpacity(0.15),
                  borderRadius: BorderRadius.circular(30),
                  border: Border.all(color: color.withOpacity(0.4)),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(classification.icon, color: color, size: 22),
                    const SizedBox(width: 8),
                    Text(
                      classification.label,
                      style: GoogleFonts.inter(
                        fontSize: 18,
                        fontWeight: FontWeight.w900,
                        color: color,
                        letterSpacing: 2,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),

              Text(
                classification.description,
                style: GoogleFonts.inter(
                  fontSize: 13,
                  color: AppTheme.textSecondary,
                  height: 1.4,
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 16),

              // Score bar
              Row(
                children: [
                  Text(
                    'Combined Score',
                    style: GoogleFonts.inter(
                      fontSize: 12,
                      color: AppTheme.textMuted,
                    ),
                  ),
                  const Spacer(),
                  Text(
                    score.toStringAsFixed(3),
                    style: GoogleFonts.jetBrainsMono(
                      fontSize: 16,
                      fontWeight: FontWeight.w700,
                      color: color,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              ClipRRect(
                borderRadius: BorderRadius.circular(4),
                child: LinearProgressIndicator(
                  value: score.clamp(0.0, 1.0),
                  backgroundColor: AppTheme.surface,
                  valueColor: AlwaysStoppedAnimation(color),
                  minHeight: 6,
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildIntegrityCard(ApkInfo info, dynamic checks) {
    final sigValid = checks?.signatureValid ?? true;
    final dexValid = checks?.dexIntegrityValid ?? true;

    return Container(
      padding: const EdgeInsets.all(20),
      decoration: AppTheme.cardDecoration(),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildCardHeader(
            Icons.verified_user,
            'APK Integrity',
            AppTheme.accentCyan,
          ),
          const SizedBox(height: 16),
          _buildIntegrityRow(
            'SHA-256 Hash',
            info.apkHash,
            true,
            isCopyable: true,
          ),
          _buildIntegrityRow(
            'Certificate Fingerprint',
            info.certFingerprint,
            true,
            isCopyable: true,
          ),
          _buildCheckRow('Signature Verification', sigValid),
          _buildCheckRow('DEX Integrity', dexValid),
          _buildCheckRow('Package Source', !info.isSideloaded,
              trueLabel: info.installer, falseLabel: 'Sideloaded'),
          _buildCheckRow('Debug Mode', !info.isDebuggable,
              trueLabel: 'Release', falseLabel: 'Debuggable ⚠️'),
        ],
      ),
    );
  }

  Widget _buildPermissionsCard(ApkInfo info) {
    final hasSensitive = info.sensitivePermissionsCount > 0;
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: AppTheme.cardDecoration(
        borderColor:
            hasSensitive ? AppTheme.accentAmber.withOpacity(0.3) : null,
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildCardHeader(
            Icons.admin_panel_settings,
            'Permissions Analysis',
            hasSensitive ? AppTheme.accentAmber : AppTheme.accentGreen,
          ),
          const SizedBox(height: 16),

          // Summary chips
          Row(
            children: [
              _buildChip(
                '${info.permissionsCount}',
                'Total',
                AppTheme.accentCyan,
              ),
              const SizedBox(width: 8),
              _buildChip(
                '${info.sensitivePermissionsCount}',
                'Sensitive',
                hasSensitive ? AppTheme.accentAmber : AppTheme.accentGreen,
              ),
            ],
          ),
          const SizedBox(height: 16),

          // Sensitive permissions list
          if (info.sensitivePermissions.isNotEmpty) ...[
            Text(
              'Sensitive Permissions:',
              style: GoogleFonts.inter(
                fontSize: 12,
                fontWeight: FontWeight.w700,
                color: AppTheme.accentAmber,
              ),
            ),
            const SizedBox(height: 8),
            ...info.sensitivePermissions.map((p) => Padding(
                  padding: const EdgeInsets.only(bottom: 4),
                  child: Row(
                    children: [
                      Icon(Icons.warning_amber,
                          size: 14,
                          color: AppTheme.accentAmber.withOpacity(0.7)),
                      const SizedBox(width: 6),
                      Expanded(
                        child: Text(
                          _formatPermission(p),
                          style: GoogleFonts.jetBrainsMono(
                            fontSize: 10,
                            color: AppTheme.textSecondary,
                          ),
                        ),
                      ),
                    ],
                  ),
                )),
          ],

          // Full permissions list (collapsible)
          const SizedBox(height: 12),
          ExpansionTile(
            tilePadding: EdgeInsets.zero,
            childrenPadding: const EdgeInsets.only(top: 8),
            title: Text(
              'All Permissions (${info.permissionsCount})',
              style: GoogleFonts.inter(
                fontSize: 12,
                color: AppTheme.textMuted,
              ),
            ),
            children: info.permissions
                .map((p) => Padding(
                      padding: const EdgeInsets.only(bottom: 3),
                      child: Text(
                        _formatPermission(p),
                        style: GoogleFonts.jetBrainsMono(
                          fontSize: 9,
                          color: AppTheme.textMuted,
                        ),
                      ),
                    ))
                .toList(),
          ),
        ],
      ),
    );
  }

  Widget _buildSecurityChecksCard(dynamic checks) {
    if (checks == null) {
      return Container(
        padding: const EdgeInsets.all(20),
        decoration: AppTheme.cardDecoration(),
        child: Column(
          children: [
            _buildCardHeader(
                Icons.security, 'Security Checks', AppTheme.accentPurple),
            const SizedBox(height: 16),
            Text(
              'No security check data available',
              style: GoogleFonts.inter(
                fontSize: 13,
                color: AppTheme.textMuted,
              ),
            ),
          ],
        ),
      );
    }

    final vectors = [
      _CheckItem('Frida Detection', checks.fridaDetected, 'CRITIQUE',
          Icons.bug_report),
      _CheckItem(
          'Runtime Hooks', checks.hookDetected, 'CRITIQUE', Icons.link_off),
      _CheckItem('Cert Pinning Bypass', checks.certPinningBypassed, 'ÉLEVÉ',
          Icons.lock_open),
      _CheckItem(
          'APK Signature', !checks.signatureValid, 'ÉLEVÉ', Icons.fingerprint),
      _CheckItem(
          'DEX Integrity', !checks.dexIntegrityValid, 'ÉLEVÉ', Icons.code),
      _CheckItem(
          'Xposed Framework', checks.xposedDetected, 'MOYEN', Icons.extension),
      _CheckItem(
          'Debugger', checks.debuggerAttached, 'MOYEN', Icons.pest_control),
      _CheckItem('Root Access', checks.rootDetected, 'FAIBLE',
          Icons.admin_panel_settings),
      _CheckItem(
          'Emulator', checks.emulatorDetected, 'INFO', Icons.phone_android),
    ];

    return Container(
      padding: const EdgeInsets.all(20),
      decoration: AppTheme.cardDecoration(),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildCardHeader(
            Icons.security,
            'Detection Vectors',
            AppTheme.accentPurple,
          ),
          const SizedBox(height: 16),
          ...vectors.map((v) => _buildVectorRow(v)),
        ],
      ),
    );
  }

  Widget _buildMetadataCard(ApkInfo info) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: AppTheme.cardDecoration(),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildCardHeader(
              Icons.info_outline, 'Package Info', AppTheme.accentCyan),
          const SizedBox(height: 16),
          _buildMetaRow('Package', info.packageName),
          _buildMetaRow('Version', '${info.versionName} (${info.versionCode})'),
          _buildMetaRow('APK Size', info.formattedSize),
          _buildMetaRow('Installer', info.installer),
          _buildMetaRow(
            'First Install',
            _formatTimestamp(info.firstInstallTime),
          ),
          _buildMetaRow(
            'Last Update',
            _formatTimestamp(info.lastUpdateTime),
          ),
        ],
      ),
    );
  }

  // ── Helpers ──

  Widget _buildCardHeader(IconData icon, String title, Color color) {
    return Row(
      children: [
        Icon(icon, color: color, size: 20),
        const SizedBox(width: 10),
        Text(
          title,
          style: GoogleFonts.inter(
            fontSize: 15,
            fontWeight: FontWeight.w700,
            color: AppTheme.textPrimary,
          ),
        ),
      ],
    );
  }

  Widget _buildIntegrityRow(String label, String value, bool valid,
      {bool isCopyable = false}) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            style: GoogleFonts.inter(
              fontSize: 11,
              color: AppTheme.textMuted,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 4),
          GestureDetector(
            onTap: isCopyable
                ? () {
                    Clipboard.setData(ClipboardData(text: value));
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(
                        content: Text('$label copied to clipboard'),
                        duration: const Duration(seconds: 1),
                        backgroundColor: AppTheme.bgCard,
                      ),
                    );
                  }
                : null,
            child: Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
              decoration: BoxDecoration(
                color: AppTheme.surface.withOpacity(0.5),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Row(
                children: [
                  Expanded(
                    child: Text(
                      value.isEmpty ? 'N/A' : value,
                      style: GoogleFonts.jetBrainsMono(
                        fontSize: 10,
                        color: AppTheme.textSecondary,
                      ),
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  if (isCopyable && value.isNotEmpty)
                    Icon(Icons.copy, size: 14, color: AppTheme.textMuted),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildCheckRow(String label, bool pass,
      {String trueLabel = 'Valid ✓', String falseLabel = 'Invalid ✗'}) {
    final color = pass ? AppTheme.accentGreen : AppTheme.accentRed;
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style:
                GoogleFonts.inter(fontSize: 12, color: AppTheme.textSecondary),
          ),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
            decoration: BoxDecoration(
              color: color.withOpacity(0.12),
              borderRadius: BorderRadius.circular(6),
            ),
            child: Text(
              pass ? trueLabel : falseLabel,
              style: GoogleFonts.jetBrainsMono(
                fontSize: 10,
                fontWeight: FontWeight.w700,
                color: color,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildVectorRow(_CheckItem item) {
    final color = item.detected ? AppTheme.accentRed : AppTheme.accentGreen;
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Row(
        children: [
          Icon(item.icon, color: color, size: 18),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  item.name,
                  style: GoogleFonts.inter(
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                    color: AppTheme.textPrimary,
                  ),
                ),
                Text(
                  'Severity: ${item.severity}',
                  style: GoogleFonts.jetBrainsMono(
                    fontSize: 9,
                    color: AppTheme.textMuted,
                  ),
                ),
              ],
            ),
          ),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
            decoration: BoxDecoration(
              color: color.withOpacity(0.12),
              borderRadius: BorderRadius.circular(6),
            ),
            child: Text(
              item.detected ? 'ALERT' : 'OK',
              style: GoogleFonts.jetBrainsMono(
                fontSize: 9,
                fontWeight: FontWeight.w700,
                color: color,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildChip(String value, String label, Color color) {
    return Expanded(
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 12),
        decoration: AppTheme.glassDecoration(tintColor: color),
        child: Column(
          children: [
            Text(
              value,
              style: GoogleFonts.jetBrainsMono(
                fontSize: 22,
                fontWeight: FontWeight.w700,
                color: color,
              ),
            ),
            const SizedBox(height: 2),
            Text(
              label,
              style: GoogleFonts.inter(
                fontSize: 10,
                color: AppTheme.textMuted,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildMetaRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style:
                GoogleFonts.inter(fontSize: 12, color: AppTheme.textSecondary),
          ),
          Flexible(
            child: Text(
              value,
              style: GoogleFonts.jetBrainsMono(
                fontSize: 11,
                color: AppTheme.textPrimary,
              ),
              textAlign: TextAlign.end,
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }

  _Classification _getClassification(ThreatLevel level) {
    switch (level) {
      case ThreatLevel.clean:
        return _Classification(
          'SAINE',
          'Application integrity verified.\nNo tampering or suspicious activity detected.',
          Icons.check_circle,
        );
      case ThreatLevel.low:
        return _Classification(
          'SAINE',
          'Application appears safe.\nMinor informational indicators detected.',
          Icons.check_circle,
        );
      case ThreatLevel.medium:
        return _Classification(
          'SUSPECTE',
          'Potential security concerns detected.\nThe environment may be modified.',
          Icons.warning_amber_rounded,
        );
      case ThreatLevel.high:
        return _Classification(
          'COMPROMISE',
          'Significant integrity issues detected.\nThe application may have been tampered with.',
          Icons.gpp_bad,
        );
      case ThreatLevel.critical:
        return _Classification(
          'COMPROMISE',
          'Critical security violations detected.\nActive attack or repackaged APK likely.',
          Icons.gpp_bad,
        );
    }
  }

  String _formatPermission(String perm) {
    return perm.replaceAll('android.permission.', '');
  }

  String _formatTimestamp(int epochMs) {
    if (epochMs == 0) return 'N/A';
    final dt = DateTime.fromMillisecondsSinceEpoch(epochMs);
    return '${dt.year}-${dt.month.toString().padLeft(2, '0')}-${dt.day.toString().padLeft(2, '0')} '
        '${dt.hour.toString().padLeft(2, '0')}:${dt.minute.toString().padLeft(2, '0')}';
  }
}

class _CheckItem {
  final String name;
  final bool detected;
  final String severity;
  final IconData icon;

  _CheckItem(this.name, this.detected, this.severity, this.icon);
}

class _Classification {
  final String label;
  final String description;
  final IconData icon;

  _Classification(this.label, this.description, this.icon);
}
