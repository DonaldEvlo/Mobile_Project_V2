import 'dart:async';
import 'dart:math';

import 'package:animate_do/animate_do.dart';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

import '../app_theme.dart';
import '../main.dart';
import '../security/external_apk_scanner.dart';
import '../security/models/security_report.dart';
import '../security/models/threat_level.dart';
import '../security/security_manager.dart';
import 'apk_analysis_screen.dart';
import 'apk_report_screen.dart';

/// Real-time security dashboard showing current threat status,
/// detection vectors, recent events, and anomaly score.
class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen>
    with TickerProviderStateMixin {
  final SecurityManager _securityManager = SecurityManager();
  final ExternalApkScanner _externalScanner = ExternalApkScanner();

  late AnimationController _pulseController;
  late AnimationController _scanController;
  late AnimationController _radarController;

  Timer? _uiRefreshTimer;
  Timer? _graphDataTimer;
  bool _isScanning = false;

  final List<double> _scoreHistory = List.filled(50, 0.0);

  @override
  void initState() {
    super.initState();

    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat(reverse: true);

    _scanController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 1),
    );

    _radarController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 3),
    )..repeat();

    // UI updates are now driven by state changes or manual interaction
    _securityManager.onThreatLevelChanged = (level) {
      if (mounted) setState(() {});
    };
  }

  @override
  void dispose() {
    _pulseController.dispose();
    _scanController.dispose();
    _radarController.dispose();
    _uiRefreshTimer?.cancel();
    _graphDataTimer?.cancel();
    super.dispose();
  }

  Future<void> _runManualScan() async {
    if (!mounted) return;
    setState(() => _isScanning = true);
    _scanController.repeat();

    // Force full scan
    await _securityManager.runFullSecurityScan();

    if (mounted) {
      _scanController.stop();
      _scanController.reset();
      setState(() {
        _isScanning = false;
        // Update graph with new score manually
        _scoreHistory.removeAt(0);
        _scoreHistory.add(_securityManager.lastAnomalyScore);
      });
    }
  }

  Future<void> _scanExternalApk() async {
    // 1. Pick APK file (local analysis only)
    final audit = await _externalScanner.pickAndAnalyzeApk();
    if (audit == null || !mounted) return; // User canceled

    // 2. Show the Qwen analysis popup dialog
    SecurityReportResponse? cloudResponse;
    bool analysisCancelled = false;

    await showDialog(
      context: context,
      barrierDismissible: false,
      builder: (dialogContext) {
        return _QwenAnalysisDialog(
          securityManager: _securityManager,
          audit: audit,
          onAnalysisComplete: (response) {
            cloudResponse = response;
            Navigator.of(dialogContext).pop();
          },
          onCancel: () {
            analysisCancelled = true;
            Navigator.of(dialogContext).pop();
          },
        );
      },
    );

    if (analysisCancelled || !mounted) return;

    // 3. Navigate to report (only when analysis is complete)
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => ApkReportScreen(
          audit: audit,
          cloudResponse: cloudResponse,
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final threat = _securityManager.currentThreatLevel;
    final checks = _securityManager.lastSecurityChecks;
    final score = _securityManager.lastAnomalyScore;

    return Scaffold(
      backgroundColor: AppTheme.backgroundColor(context),
      body: CustomScrollView(
        physics: const BouncingScrollPhysics(),
        slivers: [
          // ── App Bar ──
          SliverAppBar(
            expandedHeight: 80,
            floating: true,
            backgroundColor: AppTheme.backgroundColor(context),
            titleSpacing: 0,
            title: Row(
              children: [
                const SizedBox(width: 12),
                Container(
                  padding: const EdgeInsets.all(6),
                  decoration: BoxDecoration(
                    gradient: AppTheme.primaryGradient,
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: const Icon(
                    Icons.shield_outlined,
                    color: Colors.white,
                    size: 20,
                  ),
                ),
                const SizedBox(width: 8),
                Flexible(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        'Security Monitor',
                        style: GoogleFonts.inter(
                          fontWeight: FontWeight.w700,
                          fontSize: 15,
                          color: AppTheme.primaryText(context),
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                      Text(
                        'Live Protection Active',
                        style: GoogleFonts.inter(
                          fontSize: 9,
                          color: AppTheme.accentGreen,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
            actions: [
              IconButton(
                icon: const Icon(Icons.find_in_page,
                    color: AppTheme.textSecondary, size: 20),
                onPressed: () => Navigator.push(
                  context,
                  MaterialPageRoute(
                    builder: (_) => const ApkAnalysisScreen(),
                  ),
                ),
                tooltip: 'APK Analysis',
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(minWidth: 36),
              ),
              IconButton(
                icon: const Icon(Icons.upload_file,
                    color: AppTheme.accentAmber, size: 20),
                onPressed: _scanExternalApk,
                tooltip: 'Scan External APK',
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(minWidth: 36),
              ),
              IconButton(
                icon: Icon(
                  AppTheme.isDark(context) ? Icons.light_mode : Icons.dark_mode,
                  color: AppTheme.secondaryText(context),
                  size: 20,
                ),
                onPressed: () => AntiTamperingApp.of(context).toggleTheme(),
                tooltip: 'Toggle Theme',
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(minWidth: 36),
              ),
              RotationTransition(
                turns: _scanController,
                child: IconButton(
                  icon: Icon(
                    Icons.refresh,
                    color: _isScanning
                        ? AppTheme.accentCyan
                        : AppTheme.textSecondary,
                    size: 20,
                  ),
                  onPressed: _isScanning ? null : _runManualScan,
                  tooltip: 'Run Security Scan',
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints(minWidth: 36),
                ),
              ),
              const SizedBox(width: 4),
            ],
          ),

          SliverPadding(
            padding: const EdgeInsets.all(16),
            sliver: SliverList(
              delegate: SliverChildListDelegate([
                // ── Threat Level Card ──
                FadeInDown(
                  duration: const Duration(milliseconds: 500),
                  child: _buildThreatLevelCard(threat, score),
                ),
                const SizedBox(height: 16),

                // ── Detection Vectors Grid ──
                FadeInUp(
                  delay: const Duration(milliseconds: 200),
                  duration: const Duration(milliseconds: 500),
                  child: _buildSectionTitle('Live Detection Vectors'),
                ),
                const SizedBox(height: 12),
                FadeInUp(
                  delay: const Duration(milliseconds: 300),
                  duration: const Duration(milliseconds: 500),
                  child: _buildDetectionGrid(checks),
                ),
                const SizedBox(height: 16),

                // ── Anomaly Graph Card ──
                FadeInUp(
                  delay: const Duration(milliseconds: 400),
                  duration: const Duration(milliseconds: 500),
                  child: _buildLiveGraphCard(score),
                ),
                const SizedBox(height: 16),

                // ── System Info ──
                FadeInUp(
                  delay: const Duration(milliseconds: 500),
                  duration: const Duration(milliseconds: 500),
                  child: _buildSystemInfoCard(),
                ),
                const SizedBox(height: 32),
              ]),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildThreatLevelCard(ThreatLevel threat, double score) {
    final color = AppTheme.threatColor(threat.name);

    return AnimatedBuilder(
      animation: Listenable.merge([_pulseController, _radarController]),
      builder: (context, child) {
        final glowOpacity = threat.requiresAction
            ? 0.15 + (_pulseController.value * 0.15)
            : 0.05 + (_pulseController.value * 0.05);

        return Stack(
          alignment: Alignment.center,
          children: [
            Container(
              padding: const EdgeInsets.all(24),
              decoration: BoxDecoration(
                color: AppTheme.bgCard,
                borderRadius: BorderRadius.circular(20),
                border: Border.all(color: color.withOpacity(0.4), width: 1.5),
                boxShadow: [
                  BoxShadow(
                    color: color.withOpacity(glowOpacity),
                    blurRadius: 30,
                    spreadRadius: 2,
                  ),
                ],
              ),
              child: Column(
                children: [
                  // Status icon with Radar Effect
                  SizedBox(
                    width: 100,
                    height: 100,
                    child: Stack(
                      alignment: Alignment.center,
                      children: [
                        Container(
                          width: 80,
                          height: 80,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            gradient: LinearGradient(
                              colors: [
                                color.withOpacity(0.3),
                                color.withOpacity(0.1)
                              ],
                            ),
                            border: Border.all(
                                color: color.withOpacity(0.5), width: 2),
                          ),
                          child: Icon(
                            threat.requiresAction
                                ? Icons.warning_amber_rounded
                                : Icons.security,
                            color: color,
                            size: 40,
                          ),
                        ),
                        // Radar Sweep
                        RotationTransition(
                          turns: _radarController,
                          child: Container(
                            decoration: BoxDecoration(
                              shape: BoxShape.circle,
                              gradient: SweepGradient(
                                center: Alignment.center,
                                startAngle: 0.0,
                                endAngle: pi * 2,
                                colors: [
                                  Colors.transparent,
                                  color.withOpacity(0.1),
                                  color.withOpacity(0.4),
                                ],
                                stops: const [0.5, 0.7, 1.0],
                              ),
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 16),

                  Text(
                    threat.label.toUpperCase(),
                    style: GoogleFonts.inter(
                      fontSize: 28,
                      fontWeight: FontWeight.w900,
                      color: color,
                      letterSpacing: 3,
                    ),
                  ),
                  const SizedBox(height: 8),

                  Text(
                    'Combined Score: ${score.toStringAsFixed(3)}',
                    style: GoogleFonts.jetBrainsMono(
                      fontSize: 14,
                      color: AppTheme.textSecondary,
                    ),
                  ),
                  const SizedBox(height: 12),

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
            ),
          ],
        );
      },
    );
  }

  Widget _buildSectionTitle(String title) {
    return Row(
      children: [
        Container(
          width: 4,
          height: 20,
          decoration: BoxDecoration(
            gradient: AppTheme.primaryGradient,
            borderRadius: BorderRadius.circular(2),
          ),
        ),
        const SizedBox(width: 10),
        Text(
          title,
          style: GoogleFonts.inter(
            fontSize: 16,
            fontWeight: FontWeight.w700,
            color: AppTheme.textPrimary,
          ),
        ),
        const Spacer(),
        FadeTransition(
          opacity: _radarController,
          child: Container(
            width: 8,
            height: 8,
            decoration: const BoxDecoration(
              color: AppTheme.accentGreen,
              shape: BoxShape.circle,
            ),
          ),
        ),
        const SizedBox(width: 4),
        Text(
          'MONITORING',
          style: GoogleFonts.jetBrainsMono(
            fontSize: 10,
            color: AppTheme.accentGreen,
            fontWeight: FontWeight.bold,
          ),
        ),
      ],
    );
  }

  Widget _buildDetectionGrid(dynamic checks) {
    final detectors = [
      _DetectorInfo('Frida', Icons.bug_report, checks?.fridaDetected ?? false,
          'CRITIQUE'),
      _DetectorInfo('Root', Icons.admin_panel_settings,
          checks?.rootDetected ?? false, 'FAIBLE'),
      _DetectorInfo('Signature', Icons.fingerprint,
          !(checks?.signatureValid ?? true), 'ÉLEVÉ'),
      _DetectorInfo('DEX Hash', Icons.code,
          !(checks?.dexIntegrityValid ?? true), 'ÉLEVÉ'),
      _DetectorInfo(
          'Xposed', Icons.extension, checks?.xposedDetected ?? false, 'MOYEN'),
      _DetectorInfo('Debugger', Icons.pest_control,
          checks?.debuggerAttached ?? false, 'MOYEN'),
      _DetectorInfo('Émulateur', Icons.phone_android,
          checks?.emulatorDetected ?? false, 'INFO'),
      _DetectorInfo(
          'Hooks', Icons.link_off, checks?.hookDetected ?? false, 'CRITIQUE'),
      _DetectorInfo('Cert Pin', Icons.lock_open,
          checks?.certPinningBypassed ?? false, 'ÉLEVÉ'),
    ];

    return GridView.builder(
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 3,
        childAspectRatio: 0.95,
        crossAxisSpacing: 10,
        mainAxisSpacing: 10,
      ),
      itemCount: detectors.length,
      itemBuilder: (context, index) {
        final d = detectors[index];
        final color = d.detected ? AppTheme.accentRed : AppTheme.accentGreen;

        return Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: AppTheme.bgCard,
            borderRadius: BorderRadius.circular(14),
            border: Border.all(
              color: d.detected
                  ? AppTheme.accentRed.withOpacity(0.4)
                  : AppTheme.bgCardLight.withOpacity(0.5),
            ),
          ),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(d.icon, color: color, size: 26),
              const SizedBox(height: 8),
              Text(
                d.name,
                style: GoogleFonts.inter(
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  color: AppTheme.textPrimary,
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 4),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                decoration: BoxDecoration(
                  color: color.withOpacity(0.15),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Text(
                  d.detected ? 'ALERTE' : 'OK',
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
      },
    );
  }

  Widget _buildLiveGraphCard(double currentScore) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: AppTheme.cardDecoration(),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(
                Icons.analytics_outlined,
                color: AppTheme.accentPurple,
              ),
              const SizedBox(width: 10),
              Text(
                'Live Anomaly Score',
                style: GoogleFonts.inter(
                  fontSize: 15,
                  fontWeight: FontWeight.w700,
                  color: AppTheme.textPrimary,
                ),
              ),
              const Spacer(),
              Text(
                currentScore.toStringAsFixed(3),
                style: GoogleFonts.jetBrainsMono(
                  fontSize: 20,
                  fontWeight: FontWeight.w700,
                  color: AppTheme.threatColor(
                    ThreatLevel.fromScore(currentScore).name,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 20),

          // GRAPH AREA
          SizedBox(
            height: 100,
            width: double.infinity,
            child: CustomPaint(
              painter: GraphPainter(
                data: _scoreHistory,
                maxVal: 1.0,
                color: AppTheme.accentCyan,
              ),
            ),
          ),

          const SizedBox(height: 16),
          Row(
            children: [
              Expanded(
                child: _buildFeatureChip(
                  'Events',
                  '${_securityManager.eventBufferSize} / 50',
                  AppTheme.accentPurple,
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: _buildFeatureChip(
                  'Engine',
                  'TFLite',
                  AppTheme.accentAmber,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildFeatureChip(String label, String value, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 10, horizontal: 8),
      decoration: AppTheme.glassDecoration(tintColor: color),
      child: Column(
        children: [
          Text(
            value,
            style: GoogleFonts.jetBrainsMono(
              fontSize: 13,
              fontWeight: FontWeight.w700,
              color: color,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            label,
            style: TextStyle(fontSize: 10, color: AppTheme.textMuted),
          ),
        ],
      ),
    );
  }

  Widget _buildSystemInfoCard() {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: AppTheme.cardDecoration(),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.info_outline, color: AppTheme.accentCyan),
              const SizedBox(width: 10),
              Text(
                'System Status',
                style: GoogleFonts.inter(
                  fontSize: 15,
                  fontWeight: FontWeight.w700,
                  color: AppTheme.textPrimary,
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          _buildInfoRow(
            'Core Status',
            _securityManager.isInitialized ? 'Active' : 'Initializing',
          ),
          _buildInfoRow('Engine', 'Heuristic (Fallback)'),
          _buildInfoRow('Backend', '10.0.2.2:8000'),
          _buildInfoRow('Last Scan',
              DateTime.now().toIso8601String().split('T')[1].split('.')[0]),
        ],
      ),
    );
  }

  Widget _buildInfoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style: TextStyle(color: AppTheme.textSecondary, fontSize: 13),
          ),
          Text(
            value,
            style: GoogleFonts.jetBrainsMono(
              fontSize: 12,
              color: AppTheme.textPrimary,
            ),
          ),
        ],
      ),
    );
  }
}

/// Dialog that handles APK cloud analysis with Qwen status feedback.
///
/// Three phases:
/// 1. Checking Ollama/Qwen connectivity
/// 2. Running LLM analysis (may take 30-60s)
/// 3. Complete → auto-closes and navigates to report
class _QwenAnalysisDialog extends StatefulWidget {
  final SecurityManager securityManager;
  final ApkAudit audit;
  final void Function(SecurityReportResponse?) onAnalysisComplete;
  final VoidCallback onCancel;

  const _QwenAnalysisDialog({
    required this.securityManager,
    required this.audit,
    required this.onAnalysisComplete,
    required this.onCancel,
  });

  @override
  State<_QwenAnalysisDialog> createState() => _QwenAnalysisDialogState();
}

class _QwenAnalysisDialogState extends State<_QwenAnalysisDialog>
    with SingleTickerProviderStateMixin {
  String _phase = 'checking'; // checking, analyzing, complete, error
  String _modelName = 'qwen2.5:1.5b';
  String _statusMessage = 'Vérification de la connexion Ollama…';
  bool _ollamaReachable = false;
  late AnimationController _progressController;
  int _elapsedSeconds = 0;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _progressController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat();
    _startAnalysis();
  }

  @override
  void dispose() {
    _progressController.dispose();
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _startAnalysis() async {
    // Phase 1: Check Ollama status
    final status = await widget.securityManager.checkOllamaStatus();
    if (!mounted) return;

    setState(() {
      _ollamaReachable = status['reachable'] as bool;
      _modelName = (status['model'] as String?) ?? 'qwen2.5:1.5b';
    });

    if (!_ollamaReachable) {
      setState(() {
        _phase = 'error';
        _statusMessage = 'Impossible de contacter le serveur Ollama.\n'
            'Vérifiez que Ollama est démarré et accessible.';
      });
      return;
    }

    // Phase 2: Run LLM analysis
    setState(() {
      _phase = 'analyzing';
      _statusMessage = 'Analyse IA par $_modelName en cours…\n'
          'Cela peut prendre jusqu\'à 2 minutes.';
    });

    _timer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted) setState(() => _elapsedSeconds++);
    });

    SecurityReportResponse? response;
    try {
      response =
          await widget.securityManager.sendExternalApkAnalysis(widget.audit);
    } catch (e) {
      if (mounted) {
        setState(() {
          _phase = 'error';
          _statusMessage = 'Erreur lors de l\'analyse : $e';
        });
      }
      return;
    }

    _timer?.cancel();
    if (!mounted) return;

    if (response != null && response.llmAnalysis != null) {
      setState(() {
        _phase = 'complete';
        _statusMessage = 'Analyse terminée avec succès !';
      });
      await Future.delayed(const Duration(milliseconds: 800));
      widget.onAnalysisComplete(response);
    } else if (response != null) {
      // Got a response but no LLM analysis
      setState(() {
        _phase = 'complete';
        _statusMessage = 'Analyse statique terminée.\n'
            'Le rapport IA n\'a pas pu être généré.';
      });
      await Future.delayed(const Duration(seconds: 1));
      widget.onAnalysisComplete(response);
    } else {
      setState(() {
        _phase = 'error';
        _statusMessage = 'Le serveur n\'a pas retourné de résultat.';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Dialog(
      backgroundColor: AppTheme.bgCard,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    gradient: LinearGradient(
                      colors: [
                        AppTheme.accentPurple.withOpacity(0.3),
                        AppTheme.accentCyan.withOpacity(0.3),
                      ],
                    ),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: const Icon(
                    Icons.smart_toy_outlined,
                    color: AppTheme.accentCyan,
                    size: 28,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Analyse IA Qwen',
                        style: GoogleFonts.inter(
                          fontSize: 18,
                          fontWeight: FontWeight.w800,
                          color: AppTheme.textPrimary,
                        ),
                      ),
                      Text(
                        widget.audit.packageName,
                        style: GoogleFonts.jetBrainsMono(
                          fontSize: 11,
                          color: AppTheme.textSecondary,
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 20),

            _buildStatusIndicator(),
            const SizedBox(height: 16),

            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
              decoration: BoxDecoration(
                color: AppTheme.surface,
                borderRadius: BorderRadius.circular(20),
                border: Border.all(
                  color: AppTheme.accentPurple.withOpacity(0.3),
                ),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    _ollamaReachable ? Icons.check_circle : Icons.error_outline,
                    size: 14,
                    color: _ollamaReachable
                        ? AppTheme.accentGreen
                        : AppTheme.accentRed,
                  ),
                  const SizedBox(width: 6),
                  Text(
                    'Modèle : $_modelName',
                    style: GoogleFonts.jetBrainsMono(
                      fontSize: 11,
                      color: AppTheme.textSecondary,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),

            Text(
              _statusMessage,
              textAlign: TextAlign.center,
              style: GoogleFonts.inter(
                fontSize: 13,
                color: AppTheme.textSecondary,
                height: 1.4,
              ),
            ),

            if (_phase == 'analyzing') ...[
              const SizedBox(height: 8),
              Text(
                'Temps écoulé : ${_elapsedSeconds}s',
                style: GoogleFonts.jetBrainsMono(
                  fontSize: 12,
                  color: AppTheme.accentAmber,
                ),
              ),
            ],

            const SizedBox(height: 20),

            if (_phase == 'error')
              Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  TextButton(
                    onPressed: widget.onCancel,
                    child: Text(
                      'Fermer',
                      style: TextStyle(color: AppTheme.textSecondary),
                    ),
                  ),
                  const SizedBox(width: 8),
                  ElevatedButton(
                    onPressed: () {
                      setState(() {
                        _phase = 'checking';
                        _statusMessage = 'Nouvelle tentative…';
                        _elapsedSeconds = 0;
                      });
                      _startAnalysis();
                    },
                    style: ElevatedButton.styleFrom(
                      backgroundColor: AppTheme.accentCyan,
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(12),
                      ),
                    ),
                    child: const Text('Réessayer',
                        style: TextStyle(color: Colors.white)),
                  ),
                ],
              )
            else if (_phase == 'analyzing')
              TextButton(
                onPressed: widget.onCancel,
                child: Text(
                  'Annuler',
                  style: TextStyle(color: AppTheme.accentRed),
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildStatusIndicator() {
    switch (_phase) {
      case 'checking':
        return AnimatedBuilder(
          animation: _progressController,
          builder: (context, child) {
            return Column(
              children: [
                SizedBox(
                  width: 50,
                  height: 50,
                  child: CircularProgressIndicator(
                    strokeWidth: 3,
                    valueColor: AlwaysStoppedAnimation(
                      AppTheme.accentCyan.withOpacity(
                        0.5 + _progressController.value * 0.5,
                      ),
                    ),
                  ),
                ),
              ],
            );
          },
        );

      case 'analyzing':
        return AnimatedBuilder(
          animation: _progressController,
          builder: (context, child) {
            return Column(
              children: [
                SizedBox(
                  width: 60,
                  height: 60,
                  child: Stack(
                    alignment: Alignment.center,
                    children: [
                      CircularProgressIndicator(
                        strokeWidth: 3,
                        valueColor: AlwaysStoppedAnimation(
                          AppTheme.accentPurple.withOpacity(
                            0.4 + _progressController.value * 0.6,
                          ),
                        ),
                      ),
                      Icon(
                        Icons.psychology,
                        color: AppTheme.accentPurple,
                        size: 28,
                      ),
                    ],
                  ),
                ),
              ],
            );
          },
        );

      case 'complete':
        return const Icon(
          Icons.check_circle,
          color: AppTheme.accentGreen,
          size: 56,
        );

      case 'error':
        return const Icon(
          Icons.error_outline,
          color: AppTheme.accentRed,
          size: 56,
        );

      default:
        return const SizedBox.shrink();
    }
  }
}

class _DetectorInfo {
  final String name;
  final IconData icon;
  final bool detected;
  final String severity;

  _DetectorInfo(this.name, this.icon, this.detected, this.severity);
}

// ── CUSTOM PAINTERS ──

class GraphPainter extends CustomPainter {
  final List<double> data;
  final double maxVal;
  final Color color;

  GraphPainter({
    required this.data,
    required this.maxVal,
    required this.color,
  });

  @override
  void paint(Canvas canvas, Size size) {
    if (data.isEmpty) return;

    final paint = Paint()
      ..color = color
      ..strokeWidth = 2.0
      ..style = PaintingStyle.stroke
      ..strokeCap = StrokeCap.round;

    final path = Path();
    final dx = size.width / (data.length - 1);

    double startY = size.height - (data[0] / maxVal * size.height);
    path.moveTo(0, startY);

    for (int i = 1; i < data.length; i++) {
      double x = i * dx;
      double y = size.height - (data[i] / maxVal * size.height);

      // Bezier curve for smoothness
      double prevX = (i - 1) * dx;
      double prevY = size.height - (data[i - 1] / maxVal * size.height);

      double c1x = prevX + dx / 2;
      double c1y = prevY;
      double c2x = x - dx / 2;
      double c2y = y;

      path.cubicTo(c1x, c1y, c2x, c2y, x, y);
    }

    canvas.drawPath(path, paint);

    final fillPaint = Paint()
      ..shader = LinearGradient(
        begin: Alignment.topCenter,
        end: Alignment.bottomCenter,
        colors: [color.withOpacity(0.3), color.withOpacity(0.0)],
      ).createShader(Rect.fromLTWH(0, 0, size.width, size.height))
      ..style = PaintingStyle.fill;

    final fillPath = Path.from(path)
      ..lineTo(size.width, size.height)
      ..lineTo(0, size.height)
      ..close();

    canvas.drawPath(fillPath, fillPaint);
  }

  @override
  bool shouldRepaint(covariant GraphPainter oldDelegate) {
    return true; // Always repaint for animation
  }
}
