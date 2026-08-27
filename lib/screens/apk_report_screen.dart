import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';

import '../app_theme.dart';
import '../security/models/security_report.dart';
import '../security/models/threat_level.dart';
import '../security/security_service.dart';

/// Known risk explanations for common permissions.
const _permissionRisks = <String, String>{
  'READ_EXTERNAL_STORAGE':
      'Permet de lire toutes les données du stockage : photos, documents, données personnelles.',
  'WRITE_EXTERNAL_STORAGE':
      'Permet de modifier ou supprimer tout fichier sur le stockage externe.',
  'READ_CONTACTS':
      'Accès au carnet d\'adresses complet. Peut être utilisé pour l\'exfiltration de données.',
  'READ_SMS':
      'Lecture des SMS : peut intercepter les codes OTP et vérifications 2FA.',
  'SEND_SMS':
      'Envoi de SMS : peut envoyer des SMS surtaxés ou propager des malwares.',
  'CAMERA':
      'Accès à la caméra : peut capturer des photos/vidéos à l\'insu de l\'utilisateur.',
  'RECORD_AUDIO':
      'Enregistrement audio : peut activer le micro pour espionner.',
  'ACCESS_FINE_LOCATION':
      'Localisation GPS précise : permet le suivi de l\'utilisateur.',
  'ACCESS_COARSE_LOCATION': 'Localisation approximative via antennes et WiFi.',
  'READ_PHONE_STATE':
      'Accès à l\'identifiant téléphone (IMEI), état des appels.',
  'READ_CALL_LOG': 'Accès à l\'historique des appels.',
  'INTERNET':
      'Accès réseau : nécessaire mais peut être utilisé pour l\'exfiltration.',
  'GET_ACCOUNTS': 'Accès aux comptes configurés sur l\'appareil.',
  'RECEIVE_BOOT_COMPLETED':
      'Démarrage automatique au boot : peut servir à la persistance.',
  'SYSTEM_ALERT_WINDOW':
      'Superposition d\'écran : peut afficher de faux écrans de login (phishing).',
  'REQUEST_INSTALL_PACKAGES':
      'Demande d\'installation d\'APK : vecteur d\'installation de malware.',
  'BIND_ACCESSIBILITY_SERVICE':
      'Service d\'accessibilité : accès total aux interactions UI.',
  'BIND_DEVICE_ADMIN':
      'Admin appareil : peut verrouiller, effacer l\'appareil, changer le mot de passe.',
};

/// Dangerous permission combinations that signal specific attack vectors.
const _dangerousCombos = <String, List<String>>{
  'Exfiltration de données': ['INTERNET', 'READ_CONTACTS', 'READ_SMS'],
  'Espionnage potentiel': ['INTERNET', 'CAMERA', 'RECORD_AUDIO'],
  'Attaque par overlay': ['SYSTEM_ALERT_WINDOW', 'BIND_ACCESSIBILITY_SERVICE'],
  'Tracking utilisateur': [
    'INTERNET',
    'ACCESS_FINE_LOCATION',
    'READ_PHONE_STATE'
  ],
  'Malware persistant': [
    'RECEIVE_BOOT_COMPLETED',
    'INTERNET',
    'REQUEST_INSTALL_PACKAGES'
  ],
};

/// Known suspicious component name patterns.
const _suspiciousPatterns = <String, String>{
  'InsecureDataStorage': 'Stockage de données non sécurisé détecté.',
  'Hardcode': 'Données codées en dur (clés, mots de passe potentiels).',
  'Debug': 'Composant de débogage présent en production.',
  'Test': 'Composant de test possiblement exposé.',
  'Admin': 'Composant d\'administration potentiellement dangereux.',
  'Backdoor': 'Nom suspect évoquant une porte dérobée.',
  'Hidden': 'Composant caché — potentiel vecteur d\'attaque.',
  'Accessibility':
      'Service d\'accessibilité — accès complet aux interactions UI.',
};

/// Screen to display detailed APK analysis results, including AI verdict.
class ApkReportScreen extends StatefulWidget {
  final ApkAudit audit;
  final SecurityReportResponse? cloudResponse;

  const ApkReportScreen({
    super.key,
    required this.audit,
    this.cloudResponse,
  });

  @override
  State<ApkReportScreen> createState() => _ApkReportScreenState();
}

class _ApkReportScreenState extends State<ApkReportScreen>
    with SingleTickerProviderStateMixin {
  late AnimationController _scoreAnimController;
  late Animation<double> _scoreAnim;
  late double _finalScore;
  late ThreatLevel _threatLevel;
  late Color _color;

  @override
  void initState() {
    super.initState();
    _finalScore = _computeLocalScore();
    _threatLevel =
        widget.cloudResponse?.threatLevel ?? ThreatLevel.fromScore(_finalScore);
    _color = AppTheme.threatColor(_threatLevel.name);

    _scoreAnimController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1200),
    );
    _scoreAnim = Tween<double>(begin: 0.0, end: _finalScore).animate(
      CurvedAnimation(parent: _scoreAnimController, curve: Curves.easeOutCubic),
    );
    // Start count-up after short delay
    Future.delayed(const Duration(milliseconds: 300), () {
      if (mounted) _scoreAnimController.forward();
    });
  }

  @override
  void dispose() {
    _scoreAnimController.dispose();
    super.dispose();
  }

  /// Compute a risk score from local audit data.
  double _computeLocalScore() {
    if (widget.cloudResponse != null) return widget.cloudResponse!.score;

    final a = widget.audit;
    double score = 0.0;
    if (!a.isValid) score += 0.3;
    if (a.isDebuggable) score += 0.3;
    if (a.isSideloaded) score += 0.2;
    score += (a.sensitivePermissionsCount * 0.05).clamp(0.0, 0.3);
    if (a.permissions.length > 15) score += 0.1;
    return score.clamp(0.0, 1.0);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.backgroundColor(context),
      appBar: AppBar(
        title: Text('Rapport d\'Analyse APK', style: GoogleFonts.inter()),
        backgroundColor: Colors.transparent,
        elevation: 0,
      ),
      body: SingleChildScrollView(
        physics: const BouncingScrollPhysics(),
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // 1. Animated Score Card
            _buildAnimatedScoreCard(),
            const SizedBox(height: 20),

            // 2. AI Analysis (always shown)
            _buildAIAnalysisSection(context),
            const SizedBox(height: 20),

            // 3. Technical Details
            _buildSectionHeader('DÉTAILS TECHNIQUES', Icons.info_outlined),
            const SizedBox(height: 10),
            _buildDetailCard(widget.audit, context),
            const SizedBox(height: 20),

            // 4. Risk Indicators
            _buildSectionHeader('INDICATEURS DE RISQUE', Icons.warning_amber),
            const SizedBox(height: 10),
            _buildRiskGrid(widget.audit),
            const SizedBox(height: 20),

            // 5. Permissions with risk explanations
            if (widget.audit.permissions.isNotEmpty) ...[
              _buildSectionHeader(
                  'PERMISSIONS (${widget.audit.permissions.length})',
                  Icons.lock),
              const SizedBox(height: 10),
              _buildPermissionsSection(widget.audit),
              const SizedBox(height: 20),
            ],

            // 6. Components with suspicious highlighting
            if (_hasComponents(widget.audit)) ...[
              _buildSectionHeader('COMPOSANTS APPLICATIFS', Icons.widgets),
              const SizedBox(height: 10),
              _buildComponentsSection(widget.audit),
              const SizedBox(height: 20),
            ],

            // 7. Cloud Response Details
            if (widget.cloudResponse != null) ...[
              _buildSectionHeader(
                  'ÉVALUATION CLOUD', Icons.cloud_done_outlined),
              const SizedBox(height: 10),
              _buildCloudDetailsCard(),
              const SizedBox(height: 20),
            ],

            const SizedBox(height: 32),
          ],
        ),
      ),
    );
  }

  // ── Section Header ──

  Widget _buildSectionHeader(String title, IconData icon) {
    return Row(
      children: [
        Icon(icon, size: 16, color: AppTheme.textMuted),
        const SizedBox(width: 8),
        Text(
          title,
          style: GoogleFonts.inter(
            fontSize: 12,
            fontWeight: FontWeight.bold,
            color: AppTheme.textSecondary,
            letterSpacing: 1.2,
          ),
        ),
      ],
    );
  }

  // ── 1. Animated Score Card ──

  Widget _buildAnimatedScoreCard() {
    return AnimatedBuilder(
      animation: _scoreAnim,
      builder: (context, _) {
        final animValue = _scoreAnim.value;
        final displayPercent = (animValue * 100).toInt();

        return Container(
          padding: const EdgeInsets.all(24),
          decoration: BoxDecoration(
            color: AppTheme.bgCard,
            borderRadius: BorderRadius.circular(20),
            border: Border.all(color: _color.withOpacity(0.5)),
            boxShadow: [
              BoxShadow(
                color: _color.withOpacity(0.1),
                blurRadius: 20,
                spreadRadius: 2,
              )
            ],
          ),
          child: Row(
            children: [
              SizedBox(
                width: 90,
                height: 90,
                child: Stack(
                  alignment: Alignment.center,
                  children: [
                    SizedBox(
                      width: 90,
                      height: 90,
                      child: CircularProgressIndicator(
                        value: animValue,
                        strokeWidth: 8,
                        backgroundColor: AppTheme.surface,
                        valueColor: AlwaysStoppedAnimation(_color),
                      ),
                    ),
                    Text(
                      '$displayPercent',
                      style: GoogleFonts.inter(
                        fontSize: 28,
                        fontWeight: FontWeight.bold,
                        color: _color,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 20),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      _threatLevel.label.toUpperCase(),
                      style: GoogleFonts.inter(
                        fontSize: 22,
                        fontWeight: FontWeight.w900,
                        color: _color,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      widget.cloudResponse?.message ?? _getLocalVerdict(),
                      style: GoogleFonts.inter(
                        fontSize: 13,
                        color: AppTheme.textSecondary,
                      ),
                    ),
                    const SizedBox(height: 8),
                    ClipRRect(
                      borderRadius: BorderRadius.circular(4),
                      child: LinearProgressIndicator(
                        value: animValue,
                        backgroundColor: AppTheme.surface,
                        valueColor: AlwaysStoppedAnimation(_color),
                        minHeight: 4,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  String _getLocalVerdict() {
    if (_finalScore >= 0.7) {
      return 'Risque critique détecté. Analyse approfondie recommandée.';
    } else if (_finalScore >= 0.4) {
      return 'Risque modéré. Plusieurs indicateurs suspects détectés.';
    } else if (_finalScore > 0.0) {
      return 'Risque faible. Quelques points d\'attention mineurs.';
    }
    return 'Aucun risque majeur détecté. Application saine.';
  }

  // ── 2. AI Analysis ──

  Widget _buildAIAnalysisSection(BuildContext context) {
    final analysis = widget.cloudResponse?.llmAnalysis;
    final hasAnalysis = analysis != null && analysis.isNotEmpty;
    final displayText = hasAnalysis
        ? analysis
        : "Analyse Statique Uniquement (Serveur indisponible ou pas de réponse IA).";

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppTheme.accentPurple.withOpacity(0.3)),
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
                  'RAPPORT IA — ANALYSE DE SÉCURITÉ',
                  style: GoogleFonts.inter(
                    color: AppTheme.accentPurple,
                    fontWeight: FontWeight.w700,
                    fontSize: 12,
                    letterSpacing: 1.2,
                  ),
                ),
              ),
              if (hasAnalysis)
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                  decoration: BoxDecoration(
                    gradient: LinearGradient(
                      colors: [
                        AppTheme.accentPurple.withOpacity(0.2),
                        AppTheme.accentCyan.withOpacity(0.2),
                      ],
                    ),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(Icons.smart_toy,
                          size: 12, color: AppTheme.accentCyan),
                      const SizedBox(width: 4),
                      Text(
                        'Qwen',
                        style: GoogleFonts.jetBrainsMono(
                          fontSize: 9,
                          fontWeight: FontWeight.w700,
                          color: AppTheme.accentCyan,
                        ),
                      ),
                    ],
                  ),
                ),
              const SizedBox(width: 4),
              if (hasAnalysis)
                IconButton(
                  icon: const Icon(Icons.copy, size: 16),
                  color: AppTheme.textMuted,
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: displayText));
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                        content: Text('Analyse copiée'),
                        duration: Duration(seconds: 1),
                      ),
                    );
                  },
                ),
            ],
          ),
          const SizedBox(height: 12),
          Text(
            displayText,
            style: GoogleFonts.robotoMono(
              color: hasAnalysis ? AppTheme.textPrimary : AppTheme.textMuted,
              fontSize: 12,
              height: 1.6,
              fontStyle: hasAnalysis ? FontStyle.normal : FontStyle.italic,
            ),
          ),
        ],
      ),
    );
  }

  // ── 3. Technical Detail Card ──

  Widget _buildDetailCard(ApkAudit audit, BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: AppTheme.cardDecoration(),
      child: Column(
        children: [
          _row('Package', audit.packageName),
          const Divider(color: Colors.white10),
          _row('Version', audit.version),
          const Divider(color: Colors.white10),
          _row('Installer', audit.installerSource),
          const Divider(color: Colors.white10),
          _hashRow('Hash (SHA-256)', audit.apkHash, context),
        ],
      ),
    );
  }

  Widget _hashRow(String label, String value, BuildContext context) {
    final display = value.length > 16 ? '${value.substring(0, 16)}...' : value;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label, style: GoogleFonts.inter(color: AppTheme.textSecondary)),
          GestureDetector(
            onTap: () {
              Clipboard.setData(ClipboardData(text: value));
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(
                  content: Text('Hash copié'),
                  duration: Duration(seconds: 1),
                ),
              );
            },
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(display,
                    style: GoogleFonts.jetBrainsMono(
                        color: AppTheme.textPrimary, fontSize: 12)),
                const SizedBox(width: 4),
                const Icon(Icons.copy, size: 12, color: AppTheme.textMuted),
              ],
            ),
          ),
        ],
      ),
    );
  }

  // ── 4. Risk Indicators ──

  Widget _buildRiskGrid(ApkAudit audit) {
    final risks = <Widget>[];

    if (audit.isDebuggable) {
      risks.add(
          _riskChip('Débogage activé', AppTheme.accentRed, Icons.bug_report));
    }
    if (audit.isSideloaded) {
      risks.add(_riskChip(
          'Installation externe', AppTheme.accentAmber, Icons.download));
    }
    if (audit.sensitivePermissionsCount > 0) {
      risks.add(_riskChip('${audit.sensitivePermissionsCount} perm. sensibles',
          AppTheme.accentAmber, Icons.admin_panel_settings));
    }
    if (!audit.isValid) {
      risks.add(
          _riskChip('Signature invalide', AppTheme.accentRed, Icons.gpp_bad));
    }
    if (audit.permissions.length > 15) {
      risks.add(_riskChip('${audit.permissions.length} permissions',
          AppTheme.accentAmber, Icons.lock));
    }
    if (audit.services.isNotEmpty) {
      risks.add(_riskChip('${audit.services.length} services',
          AppTheme.accentCyan, Icons.miscellaneous_services));
    }
    if (audit.receivers.isNotEmpty) {
      risks.add(_riskChip('${audit.receivers.length} receivers',
          AppTheme.accentCyan, Icons.cell_tower));
    }
    if (audit.providers.isNotEmpty) {
      risks.add(_riskChip('${audit.providers.length} providers',
          AppTheme.accentCyan, Icons.storage));
    }

    // Check dangerous permission combinations
    final shortPerms = audit.permissions
        .map((p) => p.replaceAll('android.permission.', ''))
        .toSet();
    for (final entry in _dangerousCombos.entries) {
      final comboPerms = entry.value;
      if (comboPerms.every((p) => shortPerms.contains(p))) {
        risks.add(_riskChip(entry.key, AppTheme.accentRed, Icons.dangerous));
      }
    }

    if (risks.isEmpty) {
      risks.add(_riskChip(
          'Aucun risque détecté', AppTheme.accentGreen, Icons.check_circle));
    }

    return Wrap(spacing: 8, runSpacing: 8, children: risks);
  }

  Widget _riskChip(String label, Color color, IconData icon) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        border: Border.all(color: color.withOpacity(0.4)),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 14, color: color),
          const SizedBox(width: 6),
          Text(
            label,
            style: GoogleFonts.inter(
              color: color,
              fontWeight: FontWeight.w600,
              fontSize: 11,
            ),
          ),
        ],
      ),
    );
  }

  // ── 5. Permissions Section with Risk Explanations ──

  Widget _buildPermissionsSection(ApkAudit audit) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: AppTheme.cardDecoration(
        borderColor: audit.sensitivePermissions.isNotEmpty
            ? AppTheme.accentAmber.withOpacity(0.3)
            : null,
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (audit.sensitivePermissions.isNotEmpty) ...[
            Row(
              children: [
                const Icon(Icons.warning_amber,
                    size: 16, color: AppTheme.accentAmber),
                const SizedBox(width: 6),
                Text(
                  'Sensibles (${audit.sensitivePermissions.length})',
                  style: GoogleFonts.inter(
                    fontSize: 12,
                    fontWeight: FontWeight.w700,
                    color: AppTheme.accentAmber,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            ...audit.sensitivePermissions
                .map((p) => _permissionRowWithRisk(p, isSensitive: true)),
            const SizedBox(height: 12),
            const Divider(color: Colors.white10),
            const SizedBox(height: 8),
          ],

          // All permissions (collapsible)
          _PermissionsExpander(
            permissions: audit.permissions,
            sensitivePermissions: audit.sensitivePermissions,
            audit: audit,
          ),
        ],
      ),
    );
  }

  Widget _permissionRowWithRisk(String perm, {bool isSensitive = false}) {
    final shortName = perm.replaceAll('android.permission.', '');
    final riskExplanation = _permissionRisks[shortName];
    final color = isSensitive ? AppTheme.accentAmber : AppTheme.textMuted;

    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 6,
                height: 6,
                decoration: BoxDecoration(shape: BoxShape.circle, color: color),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  shortName,
                  style: GoogleFonts.jetBrainsMono(
                    fontSize: 10,
                    color:
                        isSensitive ? AppTheme.textPrimary : AppTheme.textMuted,
                  ),
                ),
              ),
              if (isSensitive)
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(
                    color: AppTheme.accentAmber.withOpacity(0.15),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: Text(
                    'RISQUE',
                    style: GoogleFonts.inter(
                      fontSize: 8,
                      fontWeight: FontWeight.w800,
                      color: AppTheme.accentAmber,
                    ),
                  ),
                ),
            ],
          ),
          // Risk explanation
          if (riskExplanation != null) ...[
            const SizedBox(height: 3),
            Padding(
              padding: const EdgeInsets.only(left: 14),
              child: Text(
                '⚠ $riskExplanation',
                style: GoogleFonts.inter(
                  fontSize: 9,
                  color: AppTheme.accentAmber.withOpacity(0.8),
                  height: 1.4,
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }

  // ── 6. Components Section with Suspicious Highlighting ──

  bool _hasComponents(ApkAudit audit) =>
      audit.activities.isNotEmpty ||
      audit.services.isNotEmpty ||
      audit.receivers.isNotEmpty ||
      audit.providers.isNotEmpty;

  Widget _buildComponentsSection(ApkAudit audit) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: AppTheme.cardDecoration(),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (audit.activities.isNotEmpty)
            _ComponentGroupExpander(
              title: 'Activities',
              items: audit.activities,
              itemType: 'activity',
              icon: Icons.launch,
              color: AppTheme.accentCyan,
              audit: audit,
            ),
          if (audit.services.isNotEmpty)
            _ComponentGroupExpander(
              title: 'Services',
              items: audit.services,
              itemType: 'service',
              icon: Icons.miscellaneous_services,
              color: AppTheme.accentPurple,
              audit: audit,
            ),
          if (audit.receivers.isNotEmpty)
            _ComponentGroupExpander(
              title: 'Broadcast Receivers',
              items: audit.receivers,
              itemType: 'receiver',
              icon: Icons.cell_tower,
              color: AppTheme.accentAmber,
              audit: audit,
            ),
          if (audit.providers.isNotEmpty)
            _ComponentGroupExpander(
              title: 'Content Providers',
              items: audit.providers,
              itemType: 'provider',
              icon: Icons.storage,
              color: AppTheme.accentGreen,
              audit: audit,
            ),
        ],
      ),
    );
  }

  // ── 7. Cloud Details Card ──

  Widget _buildCloudDetailsCard() {
    final resp = widget.cloudResponse!;
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: AppTheme.cardDecoration(),
      child: Column(
        children: [
          _row('Niveau de menace', resp.threatLevel.label.toUpperCase()),
          const Divider(color: Colors.white10),
          _row('Score de risque', '${(resp.score * 100).toInt()}%'),
          if (resp.action != null) ...[
            const Divider(color: Colors.white10),
            _row('Action', resp.action!.toUpperCase()),
          ],
        ],
      ),
    );
  }

  // ── Helpers ──

  Widget _row(String label, String value, {bool mono = false}) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label, style: GoogleFonts.inter(color: AppTheme.textSecondary)),
          Flexible(
            child: Text(
              value,
              style: mono
                  ? GoogleFonts.jetBrainsMono(color: AppTheme.textPrimary)
                  : GoogleFonts.inter(
                      color: AppTheme.textPrimary, fontWeight: FontWeight.w500),
              textAlign: TextAlign.end,
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }
}

/// Stateful widget for collapsible permissions list with AI analysis.
class _PermissionsExpander extends StatefulWidget {
  final List<String> permissions;
  final List<String> sensitivePermissions;
  final ApkAudit audit;

  const _PermissionsExpander({
    required this.permissions,
    required this.sensitivePermissions,
    required this.audit,
  });

  @override
  State<_PermissionsExpander> createState() => _PermissionsExpanderState();
}

class _PermissionsExpanderState extends State<_PermissionsExpander> {
  bool _expanded = false;

  @override
  Widget build(BuildContext context) {
    final nonSensitive = widget.permissions
        .where((p) => !widget.sensitivePermissions.contains(p))
        .toList();

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        GestureDetector(
          onTap: () => setState(() => _expanded = !_expanded),
          child: Row(
            children: [
              Icon(
                _expanded ? Icons.expand_less : Icons.expand_more,
                size: 18,
                color: AppTheme.textMuted,
              ),
              const SizedBox(width: 4),
              Text(
                'Toutes les permissions (${widget.permissions.length})',
                style: GoogleFonts.inter(
                  fontSize: 11,
                  color: AppTheme.textMuted,
                ),
              ),
            ],
          ),
        ),
        if (_expanded) ...[
          const SizedBox(height: 8),
          ...nonSensitive.map((p) {
            final shortName = p.replaceAll('android.permission.', '');
            final riskExplanation = _permissionRisks[shortName];
            return _PermissionTile(
              permissionName: shortName,
              fullName: p,
              staticRisk: riskExplanation,
              audit: widget.audit,
            );
          }),
        ],
      ],
    );
  }
}

/// Single permission tile with AI risk analysis on tap.
class _PermissionTile extends StatefulWidget {
  final String permissionName;
  final String fullName;
  final String? staticRisk;
  final ApkAudit audit;

  const _PermissionTile({
    required this.permissionName,
    required this.fullName,
    this.staticRisk,
    required this.audit,
  });

  @override
  State<_PermissionTile> createState() => _PermissionTileState();
}

class _PermissionTileState extends State<_PermissionTile> {
  bool _showAiExplain = false;
  bool _loadingAi = false;
  String? _aiExplanation;
  String? _aiRiskLevel;
  String? _aiRecommendation;

  Future<void> _fetchAiExplanation() async {
    if (_aiExplanation != null) {
      setState(() => _showAiExplain = !_showAiExplain);
      return;
    }
    setState(() {
      _loadingAi = true;
      _showAiExplain = true;
    });

    try {
      final service = SecurityService();
      await service.initialize();
      final result = await service.explainRisk(
        itemType: 'permission',
        itemName: widget.fullName,
        context: {
          'package_name': widget.audit.packageName,
          'all_permissions': widget.audit.permissions,
          'activities': widget.audit.activities,
          'services': widget.audit.services,
          'receivers': widget.audit.receivers,
          'providers': widget.audit.providers,
        },
      );
      if (mounted) {
        setState(() {
          _aiExplanation = result?['explanation'] ?? 'Analyse indisponible.';
          _aiRiskLevel = result?['risk_level'];
          _aiRecommendation = result?['recommendation'];
          _loadingAi = false;
        });
      }
    } catch (_) {
      if (mounted) {
        setState(() {
          _aiExplanation = 'Erreur lors de l\'analyse IA.';
          _loadingAi = false;
        });
      }
    }
  }

  Color _riskColor(String? level) {
    switch (level) {
      case 'critical':
        return AppTheme.accentRed;
      case 'high':
        return Colors.deepOrange;
      case 'medium':
        return AppTheme.accentAmber;
      case 'low':
        return AppTheme.accentGreen;
      default:
        return AppTheme.textMuted;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 4,
                height: 4,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: widget.staticRisk != null
                      ? AppTheme.accentAmber
                      : AppTheme.textMuted,
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  widget.permissionName,
                  style: GoogleFonts.jetBrainsMono(
                    fontSize: 9,
                    color: widget.staticRisk != null
                        ? AppTheme.textPrimary
                        : AppTheme.textMuted,
                  ),
                ),
              ),
              GestureDetector(
                onTap: _fetchAiExplanation,
                child: Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(
                    color: AppTheme.accentPurple.withOpacity(0.12),
                    borderRadius: BorderRadius.circular(6),
                    border: Border.all(
                        color: AppTheme.accentPurple.withOpacity(0.3)),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(
                        _loadingAi ? Icons.hourglass_top : Icons.smart_toy,
                        size: 10,
                        color: AppTheme.accentPurple,
                      ),
                      const SizedBox(width: 3),
                      Text(
                        'IA',
                        style: GoogleFonts.inter(
                          fontSize: 8,
                          fontWeight: FontWeight.w700,
                          color: AppTheme.accentPurple,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),
          if (widget.staticRisk != null)
            Padding(
              padding: const EdgeInsets.only(left: 12, top: 2),
              child: Text(
                '⚠ ${widget.staticRisk}',
                style: GoogleFonts.inter(
                  fontSize: 9,
                  color: AppTheme.accentAmber.withOpacity(0.8),
                  height: 1.4,
                ),
              ),
            ),
          if (_showAiExplain)
            Container(
              margin: const EdgeInsets.only(left: 12, top: 4, bottom: 4),
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: AppTheme.accentPurple.withOpacity(0.06),
                borderRadius: BorderRadius.circular(8),
                border:
                    Border.all(color: AppTheme.accentPurple.withOpacity(0.2)),
              ),
              child: _loadingAi
                  ? Row(
                      children: [
                        const SizedBox(
                          width: 12,
                          height: 12,
                          child: CircularProgressIndicator(
                              strokeWidth: 1.5, color: AppTheme.accentPurple),
                        ),
                        const SizedBox(width: 8),
                        Text(
                          'Analyse Qwen en cours...',
                          style: GoogleFonts.inter(
                            fontSize: 9,
                            color: AppTheme.accentPurple,
                            fontStyle: FontStyle.italic,
                          ),
                        ),
                      ],
                    )
                  : Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            const Icon(Icons.smart_toy,
                                size: 12, color: AppTheme.accentPurple),
                            const SizedBox(width: 4),
                            Text(
                              'Analyse Qwen',
                              style: GoogleFonts.inter(
                                fontSize: 9,
                                fontWeight: FontWeight.w700,
                                color: AppTheme.accentPurple,
                              ),
                            ),
                            const Spacer(),
                            if (_aiRiskLevel != null)
                              Container(
                                padding: const EdgeInsets.symmetric(
                                    horizontal: 6, vertical: 1),
                                decoration: BoxDecoration(
                                  color: _riskColor(_aiRiskLevel)
                                      .withOpacity(0.15),
                                  borderRadius: BorderRadius.circular(4),
                                ),
                                child: Text(
                                  _aiRiskLevel!.toUpperCase(),
                                  style: GoogleFonts.inter(
                                    fontSize: 7,
                                    fontWeight: FontWeight.w800,
                                    color: _riskColor(_aiRiskLevel),
                                  ),
                                ),
                              ),
                          ],
                        ),
                        const SizedBox(height: 6),
                        Text(
                          _aiExplanation ?? '',
                          style: GoogleFonts.inter(
                            fontSize: 9,
                            color: AppTheme.textPrimary,
                            height: 1.5,
                          ),
                        ),
                        if (_aiRecommendation != null &&
                            _aiRecommendation!.isNotEmpty) ...[
                          const SizedBox(height: 6),
                          Row(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              const Icon(Icons.tips_and_updates,
                                  size: 10, color: AppTheme.accentCyan),
                              const SizedBox(width: 4),
                              Expanded(
                                child: Text(
                                  _aiRecommendation!,
                                  style: GoogleFonts.inter(
                                    fontSize: 9,
                                    color: AppTheme.accentCyan,
                                    height: 1.4,
                                  ),
                                ),
                              ),
                            ],
                          ),
                        ],
                      ],
                    ),
            ),
        ],
      ),
    );
  }
}

/// Expandable component group (activities, services, etc.) with AI detail.
class _ComponentGroupExpander extends StatefulWidget {
  final String title;
  final List<String> items;
  final String itemType;
  final IconData icon;
  final Color color;
  final ApkAudit audit;

  const _ComponentGroupExpander({
    required this.title,
    required this.items,
    required this.itemType,
    required this.icon,
    required this.color,
    required this.audit,
  });

  @override
  State<_ComponentGroupExpander> createState() =>
      _ComponentGroupExpanderState();
}

class _ComponentGroupExpanderState extends State<_ComponentGroupExpander> {
  bool _expanded = false;

  String? _getSuspicionReason(String name) {
    for (final entry in _suspiciousPatterns.entries) {
      if (name.toLowerCase().contains(entry.key.toLowerCase())) {
        return entry.value;
      }
    }
    return null;
  }

  void _showComponentDetail(BuildContext context, String fullName) {
    final shortName = fullName.contains('.')
        ? fullName.substring(fullName.lastIndexOf('.') + 1)
        : fullName;
    final suspicion = _getSuspicionReason(shortName);

    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      isScrollControlled: true,
      builder: (_) => _ComponentDetailSheet(
        fullName: fullName,
        shortName: shortName,
        itemType: widget.itemType,
        suspicion: suspicion,
        audit: widget.audit,
        color: widget.color,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    // Show first 5 by default, rest when expanded
    final initialCount = 5;
    final showAll = _expanded || widget.items.length <= initialCount;
    final visibleItems =
        showAll ? widget.items : widget.items.take(initialCount).toList();
    final hiddenCount = widget.items.length - initialCount;

    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(widget.icon, size: 14, color: widget.color),
              const SizedBox(width: 6),
              Text(
                '${widget.title} (${widget.items.length})',
                style: GoogleFonts.inter(
                  fontSize: 11,
                  fontWeight: FontWeight.w700,
                  color: widget.color,
                ),
              ),
            ],
          ),
          const SizedBox(height: 6),
          ...visibleItems.map((name) {
            final shortName = name.contains('.')
                ? name.substring(name.lastIndexOf('.') + 1)
                : name;
            final suspicion = _getSuspicionReason(shortName);
            final isSuspicious = suspicion != null;

            return GestureDetector(
              onTap: () => _showComponentDetail(context, name),
              child: Padding(
                padding: const EdgeInsets.only(left: 20, bottom: 5),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Container(
                          width: 4,
                          height: 4,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            color: isSuspicious
                                ? AppTheme.accentRed
                                : widget.color.withOpacity(0.5),
                          ),
                        ),
                        const SizedBox(width: 6),
                        Expanded(
                          child: Text(
                            shortName,
                            style: GoogleFonts.jetBrainsMono(
                              fontSize: 10,
                              color: isSuspicious
                                  ? AppTheme.accentRed
                                  : AppTheme.textSecondary,
                              fontWeight: isSuspicious
                                  ? FontWeight.w700
                                  : FontWeight.normal,
                            ),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                        if (isSuspicious)
                          Container(
                            padding: const EdgeInsets.symmetric(
                                horizontal: 5, vertical: 1),
                            decoration: BoxDecoration(
                              color: AppTheme.accentRed.withOpacity(0.15),
                              borderRadius: BorderRadius.circular(4),
                            ),
                            child: Text(
                              'SUSPECT',
                              style: GoogleFonts.inter(
                                fontSize: 7,
                                fontWeight: FontWeight.w800,
                                color: AppTheme.accentRed,
                              ),
                            ),
                          ),
                        const SizedBox(width: 4),
                        Icon(Icons.chevron_right,
                            size: 14,
                            color: AppTheme.textMuted.withOpacity(0.5)),
                      ],
                    ),
                    if (isSuspicious)
                      Padding(
                        padding: const EdgeInsets.only(left: 10, top: 2),
                        child: Text(
                          '⚠ $suspicion',
                          style: GoogleFonts.inter(
                            fontSize: 9,
                            color: AppTheme.accentRed.withOpacity(0.8),
                          ),
                        ),
                      ),
                  ],
                ),
              ),
            );
          }),
          if (widget.items.length > initialCount && !_expanded)
            GestureDetector(
              onTap: () => setState(() => _expanded = true),
              child: Padding(
                padding: const EdgeInsets.only(left: 20, top: 2),
                child: Row(
                  children: [
                    const Icon(Icons.expand_more,
                        size: 14, color: AppTheme.textMuted),
                    const SizedBox(width: 4),
                    Text(
                      'Voir les $hiddenCount restants',
                      style: GoogleFonts.inter(
                        fontSize: 10,
                        color: AppTheme.accentCyan,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ],
                ),
              ),
            ),
          if (_expanded && widget.items.length > initialCount)
            GestureDetector(
              onTap: () => setState(() => _expanded = false),
              child: Padding(
                padding: const EdgeInsets.only(left: 20, top: 2),
                child: Row(
                  children: [
                    const Icon(Icons.expand_less,
                        size: 14, color: AppTheme.textMuted),
                    const SizedBox(width: 4),
                    Text(
                      'Réduire',
                      style: GoogleFonts.inter(
                        fontSize: 10,
                        color: AppTheme.textMuted,
                      ),
                    ),
                  ],
                ),
              ),
            ),
        ],
      ),
    );
  }
}

/// Bottom sheet showing detailed AI analysis of a component.
class _ComponentDetailSheet extends StatefulWidget {
  final String fullName;
  final String shortName;
  final String itemType;
  final String? suspicion;
  final ApkAudit audit;
  final Color color;

  const _ComponentDetailSheet({
    required this.fullName,
    required this.shortName,
    required this.itemType,
    this.suspicion,
    required this.audit,
    required this.color,
  });

  @override
  State<_ComponentDetailSheet> createState() => _ComponentDetailSheetState();
}

class _ComponentDetailSheetState extends State<_ComponentDetailSheet> {
  bool _loading = true;
  String? _explanation;
  String? _riskLevel;
  String? _recommendation;

  @override
  void initState() {
    super.initState();
    _fetchAiAnalysis();
  }

  Future<void> _fetchAiAnalysis() async {
    try {
      final service = SecurityService();
      await service.initialize();
      final result = await service.explainRisk(
        itemType: widget.itemType,
        itemName: widget.fullName,
        context: {
          'package_name': widget.audit.packageName,
          'all_permissions': widget.audit.permissions,
          'activities': widget.audit.activities,
          'services': widget.audit.services,
          'receivers': widget.audit.receivers,
          'providers': widget.audit.providers,
        },
      );
      if (mounted) {
        setState(() {
          _explanation = result?['explanation'] ?? 'Analyse indisponible.';
          _riskLevel = result?['risk_level'];
          _recommendation = result?['recommendation'];
          _loading = false;
        });
      }
    } catch (_) {
      if (mounted) {
        setState(() {
          _explanation = 'Erreur lors de l\'analyse IA.';
          _loading = false;
        });
      }
    }
  }

  Color _riskColor(String? level) {
    switch (level) {
      case 'critical':
        return AppTheme.accentRed;
      case 'high':
        return Colors.deepOrange;
      case 'medium':
        return AppTheme.accentAmber;
      case 'low':
        return AppTheme.accentGreen;
      default:
        return AppTheme.textMuted;
    }
  }

  @override
  Widget build(BuildContext context) {
    final typeLabels = {
      'activity': 'Activity',
      'service': 'Service',
      'receiver': 'BroadcastReceiver',
      'provider': 'ContentProvider',
    };

    return Container(
      constraints: BoxConstraints(
        maxHeight: MediaQuery.of(context).size.height * 0.7,
      ),
      decoration: const BoxDecoration(
        color: AppTheme.bgCard,
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Center(
              child: Container(
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: AppTheme.textMuted.withOpacity(0.3),
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
            ),
            const SizedBox(height: 16),

            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              decoration: BoxDecoration(
                color: widget.color.withOpacity(0.12),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: widget.color.withOpacity(0.3)),
              ),
              child: Text(
                typeLabels[widget.itemType] ?? widget.itemType,
                style: GoogleFonts.inter(
                  fontSize: 10,
                  fontWeight: FontWeight.w700,
                  color: widget.color,
                ),
              ),
            ),
            const SizedBox(height: 12),

            Text(
              widget.shortName,
              style: GoogleFonts.inter(
                fontSize: 18,
                fontWeight: FontWeight.w800,
                color: AppTheme.textPrimary,
              ),
            ),
            const SizedBox(height: 4),

            Text(
              widget.fullName,
              style: GoogleFonts.jetBrainsMono(
                fontSize: 10,
                color: AppTheme.textMuted,
              ),
            ),
            const SizedBox(height: 16),

            if (widget.suspicion != null)
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(12),
                margin: const EdgeInsets.only(bottom: 12),
                decoration: BoxDecoration(
                  color: AppTheme.accentRed.withOpacity(0.08),
                  borderRadius: BorderRadius.circular(10),
                  border:
                      Border.all(color: AppTheme.accentRed.withOpacity(0.3)),
                ),
                child: Row(
                  children: [
                    const Icon(Icons.warning_amber,
                        size: 16, color: AppTheme.accentRed),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        widget.suspicion!,
                        style: GoogleFonts.inter(
                          fontSize: 11,
                          color: AppTheme.accentRed,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                  ],
                ),
              ),

            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: AppTheme.accentPurple.withOpacity(0.06),
                borderRadius: BorderRadius.circular(12),
                border:
                    Border.all(color: AppTheme.accentPurple.withOpacity(0.2)),
              ),
              child: _loading
                  ? Column(
                      children: [
                        const SizedBox(height: 16),
                        const SizedBox(
                          width: 24,
                          height: 24,
                          child: CircularProgressIndicator(
                            strokeWidth: 2,
                            color: AppTheme.accentPurple,
                          ),
                        ),
                        const SizedBox(height: 12),
                        Text(
                          'Analyse Qwen en cours...',
                          style: GoogleFonts.inter(
                            fontSize: 11,
                            color: AppTheme.accentPurple,
                            fontStyle: FontStyle.italic,
                          ),
                        ),
                        const SizedBox(height: 16),
                      ],
                    )
                  : Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            const Icon(Icons.smart_toy,
                                size: 14, color: AppTheme.accentPurple),
                            const SizedBox(width: 6),
                            Text(
                              'Analyse IA — Qwen',
                              style: GoogleFonts.inter(
                                fontSize: 11,
                                fontWeight: FontWeight.w700,
                                color: AppTheme.accentPurple,
                              ),
                            ),
                            const Spacer(),
                            if (_riskLevel != null)
                              Container(
                                padding: const EdgeInsets.symmetric(
                                    horizontal: 8, vertical: 3),
                                decoration: BoxDecoration(
                                  color:
                                      _riskColor(_riskLevel).withOpacity(0.15),
                                  borderRadius: BorderRadius.circular(6),
                                ),
                                child: Text(
                                  _riskLevel!.toUpperCase(),
                                  style: GoogleFonts.inter(
                                    fontSize: 9,
                                    fontWeight: FontWeight.w800,
                                    color: _riskColor(_riskLevel),
                                  ),
                                ),
                              ),
                          ],
                        ),
                        const SizedBox(height: 10),
                        Text(
                          _explanation ?? '',
                          style: GoogleFonts.inter(
                            fontSize: 11,
                            color: AppTheme.textPrimary,
                            height: 1.6,
                          ),
                        ),
                        if (_recommendation != null &&
                            _recommendation!.isNotEmpty) ...[
                          const SizedBox(height: 12),
                          Container(
                            width: double.infinity,
                            padding: const EdgeInsets.all(10),
                            decoration: BoxDecoration(
                              color: AppTheme.accentCyan.withOpacity(0.08),
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: Row(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                const Icon(Icons.tips_and_updates,
                                    size: 14, color: AppTheme.accentCyan),
                                const SizedBox(width: 6),
                                Expanded(
                                  child: Text(
                                    _recommendation!,
                                    style: GoogleFonts.inter(
                                      fontSize: 10,
                                      color: AppTheme.accentCyan,
                                      height: 1.5,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ],
                      ],
                    ),
            ),
            const SizedBox(height: 20),
          ],
        ),
      ),
    );
  }
}
