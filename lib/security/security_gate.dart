import 'package:animate_do/animate_do.dart';
import 'package:anti_tampering_apk/screens/dashboard_screen.dart';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

import '../app_theme.dart';
import 'models/threat_level.dart';
import 'security_manager.dart';

/// Startup security gate that runs a full scan before allowing access.
///
/// Behavior:
/// - Shows a scanning animation during the initial check
/// - If threat < HIGH → proceeds to dashboard automatically
/// - If threat == MEDIUM → shows warning with option to continue
/// - If threat >= HIGH → shows blocking dialog with details
class SecurityGate extends StatefulWidget {
  const SecurityGate({super.key});

  @override
  State<SecurityGate> createState() => _SecurityGateState();
}

class _SecurityGateState extends State<SecurityGate>
    with TickerProviderStateMixin {
  final SecurityManager _securityManager = SecurityManager();

  late AnimationController _scanAnimController;
  late AnimationController _pulseController;

  _GateState _state = _GateState.scanning;
  ThreatLevel _detectedLevel = ThreatLevel.clean;
  String _statusText = 'Initializing security module...';
  double _progress = 0.0;

  @override
  void initState() {
    super.initState();
    _scanAnimController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat();

    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1500),
    )..repeat(reverse: true);

    _runStartupScan();
  }

  @override
  void dispose() {
    _scanAnimController.dispose();
    _pulseController.dispose();
    super.dispose();
  }

  Future<void> _runStartupScan() async {
    // Step 1: Show progress
    _updateStatus('Checking native security vectors...', 0.15);
    await Future.delayed(const Duration(milliseconds: 300));

    // Step 2: Run the actual scan
    _updateStatus('Running integrity verification...', 0.40);
    final threatLevel = await _securityManager.runFullSecurityScan();
    _detectedLevel = threatLevel;

    _updateStatus('Analyzing behavioral patterns...', 0.70);
    await Future.delayed(const Duration(milliseconds: 200));

    _updateStatus('Computing threat score...', 0.90);
    await Future.delayed(const Duration(milliseconds: 200));

    _updateStatus('Scan complete.', 1.0);
    await Future.delayed(const Duration(milliseconds: 300));

    // Step 3: Decide what to do
    if (!mounted) return;

    if (threatLevel.requiresAction) {
      // HIGH or CRITICAL → block
      setState(() => _state = _GateState.blocked);
    } else if (threatLevel == ThreatLevel.medium) {
      // MEDIUM → warn
      setState(() => _state = _GateState.warning);
    } else {
      // CLEAN or LOW → proceed
      _proceedToApp();
    }
  }

  void _updateStatus(String text, double progress) {
    if (mounted) {
      setState(() {
        _statusText = text;
        _progress = progress;
      });
    }
  }

  void _proceedToApp() {
    if (!mounted) return;
    Navigator.of(context).pushReplacement(
      PageRouteBuilder(
        pageBuilder: (_, __, ___) => const DashboardScreen(),
        transitionsBuilder: (_, animation, __, child) {
          return FadeTransition(opacity: animation, child: child);
        },
        transitionDuration: const Duration(milliseconds: 500),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.bgDark,
      body: SafeArea(
        child: Center(
          child: Padding(
            padding: const EdgeInsets.all(32),
            child: switch (_state) {
              _GateState.scanning => _buildScanningView(),
              _GateState.warning => _buildWarningView(),
              _GateState.blocked => _buildBlockedView(),
            },
          ),
        ),
      ),
    );
  }

  Widget _buildScanningView() {
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        // Animated shield
        FadeInDown(
          child: AnimatedBuilder(
            animation: _pulseController,
            builder: (context, child) {
              return Container(
                width: 120,
                height: 120,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  gradient: LinearGradient(
                    colors: [
                      AppTheme.accentCyan
                          .withOpacity(0.2 + _pulseController.value * 0.15),
                      AppTheme.accentPurple
                          .withOpacity(0.1 + _pulseController.value * 0.1),
                    ],
                  ),
                  border: Border.all(
                    color: AppTheme.accentCyan.withOpacity(0.5),
                    width: 2,
                  ),
                  boxShadow: [
                    BoxShadow(
                      color: AppTheme.accentCyan
                          .withOpacity(0.2 + _pulseController.value * 0.15),
                      blurRadius: 30,
                      spreadRadius: 5,
                    ),
                  ],
                ),
                child: RotationTransition(
                  turns: _scanAnimController,
                  child: const Icon(
                    Icons.shield_outlined,
                    color: AppTheme.accentCyan,
                    size: 50,
                  ),
                ),
              );
            },
          ),
        ),
        const SizedBox(height: 40),

        // Title
        FadeIn(
          delay: const Duration(milliseconds: 300),
          child: Text(
            'Security Verification',
            style: GoogleFonts.inter(
              fontSize: 24,
              fontWeight: FontWeight.w800,
              color: AppTheme.textPrimary,
              letterSpacing: 1,
            ),
          ),
        ),
        const SizedBox(height: 12),

        // Status text
        Text(
          _statusText,
          style: GoogleFonts.jetBrainsMono(
            fontSize: 12,
            color: AppTheme.textSecondary,
          ),
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 32),

        // Progress bar
        ClipRRect(
          borderRadius: BorderRadius.circular(4),
          child: LinearProgressIndicator(
            value: _progress,
            backgroundColor: AppTheme.surface,
            valueColor: const AlwaysStoppedAnimation(AppTheme.accentCyan),
            minHeight: 4,
          ),
        ),
        const SizedBox(height: 8),
        Text(
          '${(_progress * 100).toInt()}%',
          style: GoogleFonts.jetBrainsMono(
            fontSize: 11,
            color: AppTheme.textMuted,
          ),
        ),
      ],
    );
  }

  Widget _buildWarningView() {
    final color = AppTheme.threatColor('medium');
    final checks = _securityManager.lastSecurityChecks;
    final score = _securityManager.lastAnomalyScore;

    return FadeIn(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          // Warning icon
          Container(
            width: 100,
            height: 100,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: color.withOpacity(0.15),
              border: Border.all(color: color.withOpacity(0.5), width: 2),
            ),
            child: Icon(Icons.warning_amber_rounded, color: color, size: 50),
          ),
          const SizedBox(height: 24),

          Text(
            'MEDIUM RISK DETECTED',
            style: GoogleFonts.inter(
              fontSize: 22,
              fontWeight: FontWeight.w900,
              color: color,
              letterSpacing: 2,
            ),
          ),
          const SizedBox(height: 12),

          Text(
            'Some security checks raised concerns.\nThe application may be running in a modified environment.',
            style: GoogleFonts.inter(
              fontSize: 13,
              color: AppTheme.textSecondary,
              height: 1.5,
            ),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 8),

          Text(
            'Score: ${score.toStringAsFixed(3)}',
            style: GoogleFonts.jetBrainsMono(
              fontSize: 14,
              color: color,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 24),

          if (checks != null) _buildTriggeredChecks(checks),

          const SizedBox(height: 32),

          // Continue button
          SizedBox(
            width: double.infinity,
            child: ElevatedButton(
              onPressed: _proceedToApp,
              style: ElevatedButton.styleFrom(
                backgroundColor: color.withOpacity(0.2),
                foregroundColor: color,
                padding: const EdgeInsets.symmetric(vertical: 16),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12),
                  side: BorderSide(color: color.withOpacity(0.5)),
                ),
              ),
              child: Text(
                'Continue at your own risk',
                style: GoogleFonts.inter(fontWeight: FontWeight.w700),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildBlockedView() {
    final color = _detectedLevel == ThreatLevel.critical
        ? AppTheme.criticalColor
        : AppTheme.highColor;
    final checks = _securityManager.lastSecurityChecks;
    final score = _securityManager.lastAnomalyScore;

    return FadeIn(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          // Blocked icon
          AnimatedBuilder(
            animation: _pulseController,
            builder: (context, child) {
              return Container(
                width: 100,
                height: 100,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: color.withOpacity(0.15),
                  border: Border.all(color: color.withOpacity(0.5), width: 2),
                  boxShadow: [
                    BoxShadow(
                      color: color
                          .withOpacity(0.1 + _pulseController.value * 0.15),
                      blurRadius: 30,
                      spreadRadius: 2,
                    ),
                  ],
                ),
                child: Icon(Icons.gpp_bad, color: color, size: 50),
              );
            },
          ),
          const SizedBox(height: 24),

          Text(
            _detectedLevel == ThreatLevel.critical
                ? 'CRITICAL THREAT'
                : 'HIGH RISK DETECTED',
            style: GoogleFonts.inter(
              fontSize: 22,
              fontWeight: FontWeight.w900,
              color: color,
              letterSpacing: 2,
            ),
          ),
          const SizedBox(height: 12),

          Text(
            'Application integrity has been compromised.\n'
            'This may indicate tampering, hooking, or a repackaged APK.',
            style: GoogleFonts.inter(
              fontSize: 13,
              color: AppTheme.textSecondary,
              height: 1.5,
            ),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 8),

          Container(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            decoration: BoxDecoration(
              color: color.withOpacity(0.1),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: color.withOpacity(0.3)),
            ),
            child: Text(
              'Combined Score: ${score.toStringAsFixed(3)}',
              style: GoogleFonts.jetBrainsMono(
                fontSize: 16,
                color: color,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
          const SizedBox(height: 24),

          if (checks != null) _buildTriggeredChecks(checks),

          const SizedBox(height: 32),

          // Blocked message
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: color.withOpacity(0.08),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: color.withOpacity(0.2)),
            ),
            child: Row(
              children: [
                Icon(Icons.block, color: color, size: 20),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    'Application execution blocked for security reasons.',
                    style: GoogleFonts.inter(
                      fontSize: 12,
                      color: color,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildTriggeredChecks(dynamic checks) {
    final triggered = <String>[];
    if (checks.fridaDetected) triggered.add('🔴 Frida Detected');
    if (checks.hookDetected) triggered.add('🔴 Hooks Detected');
    if (checks.certPinningBypassed) triggered.add('🟠 Cert Pinning Bypassed');
    if (!checks.signatureValid) triggered.add('🟠 Invalid Signature');
    if (!checks.dexIntegrityValid) triggered.add('🟠 DEX Modified');
    if (checks.xposedDetected) triggered.add('🟡 Xposed Framework');
    if (checks.debuggerAttached) triggered.add('🟡 Debugger Attached');
    if (checks.rootDetected) triggered.add('🟡 Root Detected');
    if (checks.emulatorDetected) triggered.add('🔵 Emulator Detected');

    if (triggered.isEmpty) return const SizedBox.shrink();

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppTheme.bgCardLight.withOpacity(0.5)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Triggered Alerts:',
            style: GoogleFonts.inter(
              fontSize: 11,
              fontWeight: FontWeight.w700,
              color: AppTheme.textSecondary,
            ),
          ),
          const SizedBox(height: 8),
          ...triggered.map(
            (t) => Padding(
              padding: const EdgeInsets.only(bottom: 4),
              child: Text(
                t,
                style: GoogleFonts.jetBrainsMono(
                  fontSize: 11,
                  color: AppTheme.textPrimary,
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

enum _GateState { scanning, warning, blocked }
