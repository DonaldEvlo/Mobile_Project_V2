from typing import Dict, Any, List, Optional


class ThreatAnalyzer:
    """
    Static threat analyzer using calibrated weights.

    Evaluates boolean security check results with severity-based
    weights to produce a deterministic static threat score.
    """

    # Detection vector weights (from spec)
    WEIGHTS = {
        "frida_detected":        0.95,   # CRITIQUE
        "hook_detected":         0.90,   # CRITIQUE
        "cert_pinning_bypassed": 0.85,   # ÉLEVÉ
        "signature_valid":       0.80,   # ÉLEVÉ (inverted — False = threat)
        "dex_integrity_valid":   0.80,   # ÉLEVÉ (inverted — False = threat)
        "xposed_detected":       0.70,   # MOYEN
        "debugger_attached":     0.60,   # MOYEN
        "root_detected":         0.40,   # FAIBLE
        "emulator_detected":     0.20,   # INFO
    }

    # Checks where False = threat (inverted logic)
    INVERTED_CHECKS = {"signature_valid", "dex_integrity_valid"}

    def analyze_static(self, checks: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze security check results and return a static threat score.

        Uses the max-weight approach: the highest-weight triggered check
        determines the base score. This prevents low-severity checks
        from diluting critical detections.

        Args:
            checks: Dict of check_name → bool results.

        Returns:
            Dict with: score, triggered_checks, attack_indicators, severity.
        """
        triggered: List[Dict] = []
        max_score = 0.0

        for check_name, weight in self.WEIGHTS.items():
            value = checks.get(check_name)
            if value is None:
                continue

            # Determine if this check indicates a threat
            is_threat = False
            if check_name in self.INVERTED_CHECKS:
                is_threat = not value  # False = invalid = threat
            else:
                is_threat = bool(value)  # True = detected = threat

            if is_threat:
                triggered.append({
                    "check": check_name,
                    "weight": weight,
                    "severity": self._weight_to_severity(weight),
                })
                max_score = max(max_score, weight)

        # Build attack indicators from triggered checks
        attack_indicators = self._infer_attack_type(triggered)

        return {
            "score": max_score,
            "triggered_checks": triggered,
            "triggered_count": len(triggered),
            "attack_indicators": attack_indicators,
            "severity": self._weight_to_severity(max_score),
        }

    def _infer_attack_type(self, triggered: List[Dict]) -> List[str]:
        """Infer likely attack types from triggered checks."""
        indicators = []
        check_names = {t["check"] for t in triggered}

        if "frida_detected" in check_names:
            indicators.append("frida_injection")
        if "hook_detected" in check_names:
            indicators.append("runtime_hooking")
        if "cert_pinning_bypassed" in check_names:
            indicators.append("mitm_attempt")
        if "signature_valid" in check_names or "dex_integrity_valid" in check_names:
            indicators.append("apk_repackage")
        if "xposed_detected" in check_names:
            indicators.append("xposed_framework")
        if "root_detected" in check_names:
            indicators.append("rooted_device")
        if "debugger_attached" in check_names:
            indicators.append("debugging_attempt")
        if "emulator_detected" in check_names:
            indicators.append("emulator_environment")

        return indicators

    @staticmethod
    def _weight_to_severity(weight: float) -> str:
        """Convert a weight to a human-readable severity string."""
        if weight >= 0.90:
            return "CRITIQUE"
        elif weight >= 0.75:
            return "ÉLEVÉ"
        elif weight >= 0.55:
            return "MOYEN"
        elif weight >= 0.30:
            return "FAIBLE"
        return "INFO"
