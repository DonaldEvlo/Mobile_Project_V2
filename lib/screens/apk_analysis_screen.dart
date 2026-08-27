import 'dart:async';

import 'package:animate_do/animate_do.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';

import '../app_theme.dart';
import '../security/apk_info_collector.dart';
import '../security/models/security_report.dart';
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
    with TickerProviderStateMixin {
  final ApkInfoCollector _apkCollector = ApkInfoCollector();
  final SecurityManager _securityManager = SecurityManager();

  late AnimationController _pulseController;
  late AnimationController _scoreAnimController;
  late Animation<double> _scoreAnim;

  ApkInfo? _apkInfo;
  bool _isLoading = true;
  bool _isRescanning = false;
  SecurityReportResponse? _cloudResponse;
  bool _isAnalyzingCloud = false;

  /// Known permission risk explanations.
  static const _permRisks = <String, String>{
    'READ_EXTERNAL_STORAGE': 'Lecture de toutes les données du stockage.',
    'WRITE_EXTERNAL_STORAGE': 'Modification/suppression de fichiers.',
    'READ_CONTACTS': 'Accès au carnet d\'adresses.',
    'READ_SMS': 'Interception de SMS (codes OTP, 2FA).',
    'SEND_SMS': 'Envoi de SMS surtaxés ou malveillants.',
    'CAMERA': 'Capture photo/vidéo à l\'insu de l\'utilisateur.',
    'RECORD_AUDIO': 'Activation du micro pour espionnage.',
    'ACCESS_FINE_LOCATION': 'Localisation GPS précise.',
    'ACCESS_COARSE_LOCATION': 'Localisation par antennes/WiFi.',
    'READ_PHONE_STATE': 'Accès IMEI, état des appels.',
    'READ_CALL_LOG': 'Historique complet des appels.',
    'INTERNET': 'Accès réseau — vecteur d\'exfiltration.',
    'SYSTEM_ALERT_WINDOW': 'Superposition d\'écran (phishing).',
    'REQUEST_INSTALL_PACKAGES': 'Installation d\'APK (malware).',
    'BIND_ACCESSIBILITY_SERVICE': 'Accès total aux interactions UI.',
    'BIND_DEVICE_ADMIN': 'Contrôle complet de l\'appareil.',
    'RECEIVE_BOOT_COMPLETED': 'Démarrage auto au boot (persistance).',
    'GET_ACCOUNTS': 'Accès aux comptes configurés.',
  };

  @override
  void initState() {
    super.initState();
    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat(reverse: true);

    _scoreAnimController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1200),
    );
    _scoreAnim = Tween<double>(begin: 0.0, end: 0.0).animate(
      CurvedAnimation(parent: _scoreAnimController, curve: Curves.easeOutCubic),
    );

    _loadApkInfo();
  }

  @override
  void dispose() {
    _pulseController.dispose();
    _scoreAnimController.dispose();
    super.dispose();
  }

  void _animateScoreTo(double target) {
    _scoreAnim = Tween<double>(begin: 0.0, end: target).animate(
      CurvedAnimation(parent: _scoreAnimController, curve: Curves.easeOutCubic),
    );
    _scoreAnimController.forward(from: 0);
  }

  Future<void> _loadApkInfo() async {
    final info = await _apkCollector.collectApkInfo();
    if (!mounted) return;
    setState(() {
      _apkInfo = info;
      _isLoading = false;
    });

    final score = _securityManager.lastAnomalyScore;
    Future.delayed(const Duration(milliseconds: 300), () {
      if (mounted) _animateScoreTo(score);
    });

    // Also trigger cloud AI analysis (with timeout)
    _fetchCloudAnalysis();
  }

  Future<void> _fetchCloudAnalysis() async {
    if (_isAnalyzingCloud || !mounted) return;
    setState(() => _isAnalyzingCloud = true);
    try {
      final response = await _securityManager
          .sendSelfApkAnalysis()
          .timeout(const Duration(seconds: 130));
      if (mounted && response != null) {
        setState(() => _cloudResponse = response);
      }
    } catch (e) {
      // Offline mode or timeout — no cloud analysis
    } finally {
      if (mounted) setState(() => _isAnalyzingCloud = false);
    }
  }

  Future<void> _rescan() async {
    if (!mounted) return;
    setState(() => _isRescanning = true);
    _apkCollector.clearCache();
    await _securityManager.runFullSecurityScan();
    await _loadApkInfo();
    if (mounted) setState(() => _isRescanning = false);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.backgroundColor(context),
      appBar: AppBar(
        backgroundColor: AppTheme.backgroundColor(context),
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

          // ── Score Correlation card ──
          FadeInUp(
            delay: const Duration(milliseconds: 350),
            duration: const Duration(milliseconds: 400),
            child: _buildCorrelationCard(score),
          ),
          const SizedBox(height: 16),

          // ── AI Synthesis Report card ──
          FadeInUp(
            delay: const Duration(milliseconds: 400),
            duration: const Duration(milliseconds: 400),
            child: _buildAIReportCard(),
          ),
          const SizedBox(height: 16),

          // ── Package Metadata card ──
          FadeInUp(
            delay: const Duration(milliseconds: 450),
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
      animation: Listenable.merge([_pulseController, _scoreAnim]),
      builder: (context, child) {
        final animScore = _scoreAnim.value;
        final displayPercent = (animScore * 100).toInt();

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

              SizedBox(
                width: 80,
                height: 80,
                child: Stack(
                  alignment: Alignment.center,
                  children: [
                    SizedBox(
                      width: 80,
                      height: 80,
                      child: CircularProgressIndicator(
                        value: animScore.clamp(0.0, 1.0),
                        strokeWidth: 7,
                        backgroundColor: AppTheme.surface,
                        valueColor: AlwaysStoppedAnimation(color),
                      ),
                    ),
                    Text(
                      '$displayPercent',
                      style: GoogleFonts.inter(
                        fontSize: 24,
                        fontWeight: FontWeight.bold,
                        color: color,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 12),

              Row(
                children: [
                  Text(
                    'Score combiné',
                    style: GoogleFonts.inter(
                      fontSize: 12,
                      color: AppTheme.textMuted,
                    ),
                  ),
                  const Spacer(),
                  Text(
                    animScore.toStringAsFixed(3),
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
                  value: animScore.clamp(0.0, 1.0),
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
            'Analyse des Permissions',
            hasSensitive ? AppTheme.accentAmber : AppTheme.accentGreen,
          ),
          const SizedBox(height: 16),

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
                'Sensibles',
                hasSensitive ? AppTheme.accentAmber : AppTheme.accentGreen,
              ),
            ],
          ),
          const SizedBox(height: 16),

          // Sensitive permissions with risk explanations
          if (info.sensitivePermissions.isNotEmpty) ...[
            Text(
              'Permissions Sensibles:',
              style: GoogleFonts.inter(
                fontSize: 12,
                fontWeight: FontWeight.w700,
                color: AppTheme.accentAmber,
              ),
            ),
            const SizedBox(height: 8),
            ...info.sensitivePermissions.map((p) {
              final shortName = _formatPermission(p);
              final risk = _permRisks[shortName];
              return Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Icon(Icons.warning_amber,
                            size: 14,
                            color: AppTheme.accentAmber.withOpacity(0.7)),
                        const SizedBox(width: 6),
                        Expanded(
                          child: Text(
                            shortName,
                            style: GoogleFonts.jetBrainsMono(
                              fontSize: 10,
                              color: AppTheme.textSecondary,
                            ),
                          ),
                        ),
                        Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 5, vertical: 1),
                          decoration: BoxDecoration(
                            color: AppTheme.accentAmber.withOpacity(0.15),
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: Text(
                            'RISQUE',
                            style: GoogleFonts.inter(
                              fontSize: 7,
                              fontWeight: FontWeight.w800,
                              color: AppTheme.accentAmber,
                            ),
                          ),
                        ),
                      ],
                    ),
                    if (risk != null)
                      Padding(
                        padding: const EdgeInsets.only(left: 20, top: 3),
                        child: Text(
                          '⚠ $risk',
                          style: GoogleFonts.inter(
                            fontSize: 9,
                            color: AppTheme.accentAmber.withOpacity(0.8),
                            height: 1.4,
                          ),
                        ),
                      ),
                  ],
                ),
              );
            }),
          ],

          // Full permissions list (collapsible)
          const SizedBox(height: 12),
          ExpansionTile(
            tilePadding: EdgeInsets.zero,
            childrenPadding: const EdgeInsets.only(top: 8),
            title: Text(
              'Toutes les Permissions (${info.permissionsCount})',
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

  Widget _buildCorrelationCard(double score) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: AppTheme.cardDecoration(
        borderColor: AppTheme.accentCyan.withOpacity(0.3),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildCardHeader(
            Icons.compare_arrows,
            'Corrélation des Scores',
            AppTheme.accentCyan,
          ),
          const SizedBox(height: 12),
          Text(
            'Le score combiné (${score.toStringAsFixed(3)}) affiché sur la page '
            'd\'accueil est calculé ainsi :',
            style: GoogleFonts.inter(
              fontSize: 12,
              color: AppTheme.textSecondary,
              height: 1.5,
            ),
          ),
          const SizedBox(height: 10),
          _buildFormulaRow('Score statique', '60%',
              'Checks natifs (Frida, root, signature, hooks, émulateur, Xposed)'),
          _buildFormulaRow('Score comportemental', '40%',
              'Modèle TFLite sur les événements (réseau, fichiers, IPC)'),
          const Divider(color: Colors.white10, height: 20),
          Text(
            'Les métriques ci-dessous détaillent les vérifications individuelles '
            'qui composent le score statique.',
            style: GoogleFonts.inter(
              fontSize: 11,
              color: AppTheme.textMuted,
              fontStyle: FontStyle.italic,
              height: 1.4,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildFormulaRow(String label, String weight, String detail) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
            decoration: BoxDecoration(
              color: AppTheme.accentCyan.withOpacity(0.12),
              borderRadius: BorderRadius.circular(4),
            ),
            child: Text(
              weight,
              style: GoogleFonts.jetBrainsMono(
                fontSize: 10,
                fontWeight: FontWeight.w700,
                color: AppTheme.accentCyan,
              ),
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  label,
                  style: GoogleFonts.inter(
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                    color: AppTheme.textPrimary,
                  ),
                ),
                Text(
                  detail,
                  style: GoogleFonts.inter(
                    fontSize: 10,
                    color: AppTheme.textMuted,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildAIReportCard() {
    if (_isAnalyzingCloud) {
      return Container(
        padding: const EdgeInsets.all(20),
        decoration: AppTheme.cardDecoration(
          borderColor: AppTheme.accentPurple.withOpacity(0.3),
        ),
        child: Column(
          children: [
            _buildCardHeader(
              Icons.psychology,
              'Rapport IA',
              AppTheme.accentPurple,
            ),
            const SizedBox(height: 16),
            const SizedBox(
              width: 24,
              height: 24,
              child: CircularProgressIndicator(
                strokeWidth: 2,
                color: AppTheme.accentPurple,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'Analyse IA en cours...',
              style: GoogleFonts.inter(
                fontSize: 12,
                color: AppTheme.textMuted,
              ),
            ),
          ],
        ),
      );
    }

    final analysis = _cloudResponse?.llmAnalysis;
    if (analysis == null || analysis.isEmpty) {
      return Container(
        padding: const EdgeInsets.all(20),
        decoration: AppTheme.cardDecoration(
          borderColor: AppTheme.accentPurple.withOpacity(0.2),
        ),
        child: Column(
          children: [
            _buildCardHeader(
              Icons.psychology,
              'Rapport IA',
              AppTheme.accentPurple,
            ),
            const SizedBox(height: 12),
            Text(
              _cloudResponse == null
                  ? 'Analyse Statique Uniquement (Serveur indisponible).'
                  : 'Analyse Statique Uniquement (Pas de rapport IA).',
              style: GoogleFonts.inter(
                fontSize: 12,
                color: AppTheme.textMuted,
                fontWeight: FontWeight.w500,
              ),
            ),
          ],
        ),
      );
    }

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: AppTheme.cardDecoration(
        borderColor: AppTheme.accentPurple.withOpacity(0.4),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.psychology,
                  color: AppTheme.accentPurple, size: 20),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  'RAPPORT SYNTHÉTIQUE IA',
                  style: GoogleFonts.inter(
                    color: AppTheme.accentPurple,
                    fontWeight: FontWeight.w700,
                    fontSize: 12,
                    letterSpacing: 1.2,
                  ),
                ),
              ),
              if (_cloudResponse != null)
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                  decoration: BoxDecoration(
                    color:
                        AppTheme.threatColor(_cloudResponse!.threatLevel.name)
                            .withOpacity(0.15),
                    borderRadius: BorderRadius.circular(6),
                  ),
                  child: Text(
                    'Score: ${(_cloudResponse!.score * 100).toInt()}%',
                    style: GoogleFonts.jetBrainsMono(
                      fontSize: 10,
                      fontWeight: FontWeight.w700,
                      color: AppTheme.threatColor(
                          _cloudResponse!.threatLevel.name),
                    ),
                  ),
                ),
              const SizedBox(width: 4),
              IconButton(
                icon: const Icon(Icons.copy, size: 16),
                color: AppTheme.textMuted,
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(minWidth: 28),
                onPressed: () {
                  Clipboard.setData(ClipboardData(text: analysis));
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(
                      content: Text('Rapport copié'),
                      duration: Duration(seconds: 1),
                    ),
                  );
                },
              ),
            ],
          ),
          const SizedBox(height: 12),
          Text(
            analysis,
            style: GoogleFonts.inter(
              color: AppTheme.textPrimary,
              fontSize: 12,
              height: 1.6,
            ),
          ),
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
