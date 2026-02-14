/// Threat levels aligned with backend scoring thresholds.
///
/// Score ranges:
/// - CLEAN:    < 0.20
/// - LOW:      0.20 - 0.40
/// - MEDIUM:   0.40 - 0.65
/// - HIGH:     0.65 - 0.85
/// - CRITICAL: > 0.85
enum ThreatLevel {
  clean,
  low,
  medium,
  high,
  critical;

  /// Convert a combined score to a threat level.
  static ThreatLevel fromScore(double score) {
    if (score > 0.85) return ThreatLevel.critical;
    if (score > 0.65) return ThreatLevel.high;
    if (score > 0.40) return ThreatLevel.medium;
    if (score > 0.20) return ThreatLevel.low;
    return ThreatLevel.clean;
  }

  /// Parse from backend string response.
  static ThreatLevel fromString(String value) {
    return ThreatLevel.values.firstWhere(
      (e) => e.name == value.toLowerCase(),
      orElse: () => ThreatLevel.clean,
    );
  }

  /// Human-readable label.
  String get label {
    switch (this) {
      case ThreatLevel.clean:
        return 'Clean';
      case ThreatLevel.low:
        return 'Low Risk';
      case ThreatLevel.medium:
        return 'Medium Risk';
      case ThreatLevel.high:
        return 'High Risk';
      case ThreatLevel.critical:
        return 'CRITICAL';
    }
  }

  /// Whether this level requires immediate action.
  bool get requiresAction =>
      this == ThreatLevel.high || this == ThreatLevel.critical;

  /// Whether LLM enrichment should be triggered.
  bool get requiresLlmAnalysis =>
      this == ThreatLevel.medium ||
      this == ThreatLevel.high ||
      this == ThreatLevel.critical;
}
