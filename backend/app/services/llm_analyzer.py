import json
from typing import Optional, Dict, Any

import httpx

from app.core.config import get_settings

settings = get_settings()


class OllamaAnalyzer:
    """
    LLM integration with Ollama for security incident analysis.

    Three use cases:
    1. Incident narrative analysis (per-report)
    2. Multi-incident correlation (periodic batch)
    3. Critical alert validation (false positive reduction)

    Ollama runs asynchronously — never blocks the detection pipeline.
    """

    async def analyze_incident(
        self,
        report_data: Dict[str, Any],
        threat_level: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Generate a structured narrative analysis of a security incident.

        Args:
            report_data: The full security report payload.
            threat_level: Determined threat level (medium/high/critical).

        Returns:
            Dict with: explanation, risk_level, false_positive_probability,
            recommended_actions, confidence.
        """
        prompt = self._build_analysis_prompt(report_data, threat_level)
        response = await self._query_ollama(prompt)

        if response is None:
            return None

        return self._parse_analysis_response(response)

    async def correlate_incidents(
        self,
        recent_incidents: list[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze patterns across multiple recent incidents.

        Called periodically (every 15 minutes) to detect coordinated
        attack campaigns and common patterns between devices.
        """
        if not recent_incidents:
            return None

        prompt = self._build_correlation_prompt(recent_incidents)
        response = await self._query_ollama(prompt)

        if response is None:
            return None

        return self._parse_correlation_response(response)

    async def validate_critical_alert(
        self,
        report_data: Dict[str, Any],
        static_score: float,
        ml_score: float,
    ) -> Optional[Dict[str, Any]]:
        """
        Validate whether a critical alert is a true positive.

        Called before triggering force_logout to reduce false positives.
        """
        prompt = self._build_validation_prompt(report_data, static_score, ml_score)
        response = await self._query_ollama(prompt)

        if response is None:
            return {"is_true_positive": True, "confidence": 0.5}

        return self._parse_validation_response(response)

    async def _query_ollama(self, prompt: str) -> Optional[str]:
        """Send a prompt to the Ollama API and return the response text."""
        try:
            async with httpx.AsyncClient(timeout=settings.OLLAMA_TIMEOUT) as client:
                response = await client.post(
                    f"{settings.OLLAMA_URL}/api/generate",
                    json={
                        "model": settings.OLLAMA_MODEL,
                        "prompt": prompt,
                        "stream": False,
                        "options": {
                            "temperature": 0.3,
                            "num_predict": 500,
                        },
                    },
                )

                if response.status_code == 200:
                    data = response.json()
                    return data.get("response", "")
                else:
                    print(f"[LLM] Ollama returned status {response.status_code}")
                    return None

        except httpx.ConnectError:
            print("[LLM] Cannot connect to Ollama — service may be down")
            return None
        except httpx.TimeoutException:
            print("[LLM] Ollama request timed out")
            return None
        except Exception as e:
            print(f"[LLM] Ollama query error: {e}")
            return None

    def _build_analysis_prompt(self, report: Dict, threat_level: str) -> str:
        checks = report.get("security_checks", {})
        features = report.get("behavior_features", {})

        return f"""You are a mobile security analyst. Analyze this security incident report and respond in JSON format.

INCIDENT DATA:
- Threat Level: {threat_level}
- Device ID: {report.get('device_id', 'unknown')}
- Security Checks:
  - Frida Detected: {checks.get('frida_detected', False)}
  - Root Detected: {checks.get('root_detected', False)}
  - Signature Valid: {checks.get('signature_valid', True)}
  - DEX Integrity Valid: {checks.get('dex_integrity_valid', True)}
  - Xposed Detected: {checks.get('xposed_detected', False)}
  - Debugger Attached: {checks.get('debugger_attached', False)}
  - Emulator Detected: {checks.get('emulator_detected', False)}
  - Hook Detected: {checks.get('hook_detected', False)}
  - Cert Pinning Bypassed: {checks.get('cert_pinning_bypassed', False)}
- Behavioral Features:
  - Network Calls: {features.get('network_calls_count', 0)}
  - File Accesses: {features.get('file_access_count', 0)}
  - Timing Entropy: {features.get('timing_entropy', 0.5)}
  - Memory Anomaly Score: {features.get('memory_anomaly_score', 0)}
  - CPU Spikes: {features.get('cpu_spike_count', 0)}

Respond with ONLY valid JSON:
{{
  "explanation": "Technical analysis of what is happening",
  "risk_level": "low|medium|high|critical",
  "false_positive_probability": 0.0-1.0,
  "attack_type": "identified attack type or null",
  "recommended_actions": ["action1", "action2"],
  "confidence": 0.0-1.0
}}"""

    def _build_correlation_prompt(self, incidents: list[Dict]) -> str:
        summary = json.dumps(
            [
                {
                    "device_id": i.get("device_id"),
                    "threat_level": i.get("threat_level"),
                    "attack_type": i.get("attack_type"),
                    "score": i.get("combined_score"),
                }
                for i in incidents[:20]
            ],
            indent=2,
        )

        return f"""You are a security analyst. Analyze these {len(incidents)} recent security incidents for patterns.

RECENT INCIDENTS:
{summary}

Look for:
1. Coordinated attack campaigns (same attack across devices)
2. Common patterns between devices
3. Targeted app versions
4. Time-based attack patterns

Respond with ONLY valid JSON:
{{
  "campaign_detected": true/false,
  "campaign_type": "description or null",
  "affected_devices": ["device_id1", ...],
  "pattern_description": "analysis",
  "severity": "low|medium|high|critical",
  "recommendations": ["action1", "action2"]
}}"""

    def _build_validation_prompt(
        self, report: Dict, static_score: float, ml_score: float
    ) -> str:
        return f"""You are a security analyst. Determine if this critical alert is a TRUE POSITIVE or FALSE POSITIVE.

SCORES:
- Static Score: {static_score:.3f}
- ML Score: {ml_score:.3f}
- Security Checks: {json.dumps(report.get('security_checks', {}))}
- Behavioral Features: {json.dumps(report.get('behavior_features', {}))}

Consider:
- Could this be a developer debugging?
- Could this be a power user with a rooted device?
- Do the behavioral features support the static checks?

Respond with ONLY valid JSON:
{{
  "is_true_positive": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "explanation"
}}"""

    def _parse_analysis_response(self, response: str) -> Optional[Dict]:
        return self._parse_json_response(response)

    def _parse_correlation_response(self, response: str) -> Optional[Dict]:
        return self._parse_json_response(response)

    def _parse_validation_response(self, response: str) -> Optional[Dict]:
        result = self._parse_json_response(response)
        if result is None:
            return {"is_true_positive": True, "confidence": 0.5}
        return result

    def _parse_json_response(self, response: str) -> Optional[Dict]:
        """Extract JSON from LLM response, handling markdown code blocks."""
        try:
            # Try direct parse
            return json.loads(response)
        except json.JSONDecodeError:
            pass

        # Try extracting from markdown code block
        try:
            start = response.find("{")
            end = response.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(response[start:end])
        except json.JSONDecodeError:
            pass

        print(f"[LLM] Failed to parse response as JSON")
        return None
