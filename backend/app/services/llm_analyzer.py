import json
from typing import Optional, Dict, Any

import httpx

from app.core.config import get_settings

settings = get_settings()


class OllamaAnalyzer:
    """
    LLM integration with Ollama for security incident analysis.

    Optimized for Qwen 2.5 1.5B — uses concise prompts with clear
    separation between instructions and expected JSON schema.
    """

    # ── Public API ──

    async def analyze_incident(
        self,
        report_data: Dict[str, Any],
        threat_level: str,
    ) -> Optional[Dict[str, Any]]:
        """Generate a structured narrative analysis of a security incident."""
        prompt = self._build_analysis_prompt(report_data, threat_level)
        response = await self._query_ollama(prompt, max_tokens=2048)

        if response is None:
            return None

        return self._parse_json_response(response)

    async def correlate_incidents(
        self,
        recent_incidents: list[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Analyze patterns across multiple recent incidents."""
        if not recent_incidents:
            return None

        prompt = self._build_correlation_prompt(recent_incidents)
        response = await self._query_ollama(prompt, max_tokens=1024)

        if response is None:
            return None

        return self._parse_json_response(response)

    async def validate_critical_alert(
        self,
        report_data: Dict[str, Any],
        static_score: float,
        ml_score: float,
    ) -> Optional[Dict[str, Any]]:
        """Validate whether a critical alert is a true positive."""
        prompt = self._build_validation_prompt(report_data, static_score, ml_score)
        response = await self._query_ollama(prompt, max_tokens=512)

        if response is None:
            return {"is_true_positive": True, "confidence": 0.5}

        return self._parse_json_response(response) or {"is_true_positive": True, "confidence": 0.5}

    async def explain_single_item(
        self,
        item_type: str,
        item_name: str,
        context: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Generate a focused risk explanation for a single APK component."""
        prompt = self._build_item_explanation_prompt(item_type, item_name, context)
        response = await self._query_ollama(prompt, max_tokens=512)

        if response is None:
            return None

        return self._parse_json_response(response)

    # ── Ollama Communication ──

    async def _query_ollama(self, prompt: str, max_tokens: int = 2048) -> Optional[str]:
        """Send a prompt to Ollama and return the response text."""
        try:
            timeout = httpx.Timeout(
                connect=10.0,
                read=float(settings.OLLAMA_TIMEOUT),
                write=10.0,
                pool=10.0,
            )
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    f"{settings.OLLAMA_URL}/api/generate",
                    json={
                        "model": settings.OLLAMA_MODEL,
                        "system": (
                            "Tu es un analyste expert en cybersécurité mobile Android. "
                            "Réponds TOUJOURS en JSON valide. Ne mets JAMAIS de texte en dehors du JSON. "
                            "Remplis CHAQUE champ avec du contenu RÉEL et SPÉCIFIQUE, pas des descriptions génériques."
                        ),
                        "prompt": prompt,
                        "format": "json",
                        "stream": False,
                        "options": {
                            "temperature": 0.4,
                            "num_predict": max_tokens,
                            "top_p": 0.9,
                        },
                    },
                )

                if response.status_code == 200:
                    data = response.json()
                    result = data.get("response", "")
                    if not result or not result.strip():
                        print("[LLM] Ollama returned empty response")
                        return None
                    return result
                else:
                    body = response.text[:500]
                    print(f"[LLM] Ollama returned status {response.status_code}: {body}")
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

    # ── Prompt Builders ──

    def _build_analysis_prompt(self, report: Dict, threat_level: str) -> str:
        task_type = report.get("task", "INCIDENT_ANALYSIS")

        if task_type == "APK_ANALYSIS":
            return self._build_apk_analysis_prompt(report, threat_level)
        return self._build_incident_prompt(report, threat_level)

    def _build_apk_analysis_prompt(self, report: Dict, threat_level: str) -> str:
        pkg = report.get('package_name', 'inconnu')
        ver = report.get('version', '?')
        debug = report.get('debuggable', False)
        side = report.get('sideloaded', False)
        perms = report.get('all_permissions', [])
        sensitive = report.get('sensitive_permissions', [])
        activities = report.get('activities', [])
        services = report.get('services', [])
        receivers = report.get('receivers', [])
        providers = report.get('providers', [])

        data_block = f"""Package: {pkg} v{ver}
Debuggable: {debug} | Sideloaded: {side} | Menace: {threat_level}
Permissions sensibles ({len(sensitive)}): {', '.join(sensitive[:15]) if sensitive else 'aucune'}
Toutes permissions ({len(perms)}): {', '.join(perms[:20]) if perms else 'aucune'}
Activities: {', '.join(activities[:10]) if activities else 'aucune'}
Services: {', '.join(services[:10]) if services else 'aucun'}
Receivers: {', '.join(receivers[:10]) if receivers else 'aucun'}
Providers: {', '.join(providers[:10]) if providers else 'aucun'}"""

        return f"""Analyse cette application Android et donne un rapport de sécurité COMPLET en français.

{data_block}

Rédige une analyse DÉTAILLÉE qui couvre:
- Les risques de chaque permission sensible
- Les composants suspects dans les activities/services/receivers
- Les combinaisons dangereuses de permissions (ex: INTERNET + READ_SMS = exfiltration)
- Si debuggable=True: les vecteurs d'attaque que ça ouvre
- Un verdict final avec le niveau de risque global

Réponds en JSON:
{{
  "explanation": "[RÉDIGE ICI un paragraphe de 5-10 phrases décrivant les vulnérabilités SPÉCIFIQUES trouvées dans {pkg}]",
  "risk_level": "[une valeur parmi: low, medium, high, critical]",
  "false_positive_probability": 0.1,
  "attack_type": "[type d'attaque identifié ou null]",
  "recommended_actions": ["action concrète 1", "action concrète 2"],
  "confidence": 0.8
}}"""

    def _build_incident_prompt(self, report: Dict, threat_level: str) -> str:
        checks = report.get("security_checks", {})
        features = report.get("behavior_features", {})

        triggered = []
        check_map = {
            "frida_detected": "Frida détecté",
            "root_detected": "Root détecté",
            "xposed_detected": "Xposed détecté",
            "debugger_attached": "Debugger attaché",
            "emulator_detected": "Émulateur détecté",
            "hook_detected": "Hook détecté",
            "cert_pinning_bypassed": "Cert pinning contourné",
        }
        for key, label in check_map.items():
            if checks.get(key, False):
                triggered.append(label)

        if not checks.get("signature_valid", True):
            triggered.append("Signature invalide")
        if not checks.get("dex_integrity_valid", True):
            triggered.append("DEX corrompu")

        alerts_str = ', '.join(triggered) if triggered else 'aucune alerte'

        return f"""Analyse cet incident de sécurité mobile.

Menace: {threat_level} | Device: {report.get('device_id', '?')}
Alertes déclenchées: {alerts_str}
Réseau: {features.get('network_calls_count', 0)} appels | Fichiers: {features.get('file_access_count', 0)} accès
Entropie timing: {features.get('timing_entropy', 0.5)} | Anomalie mémoire: {features.get('memory_anomaly_score', 0)}

Rédige une analyse en français des risques de sécurité détectés.

Réponds en JSON:
{{
  "explanation": "[ÉCRIS un paragraphe détaillé expliquant les risques spécifiques de cet incident]",
  "risk_level": "[low, medium, high ou critical]",
  "false_positive_probability": 0.3,
  "attack_type": "[type d'attaque ou null]",
  "recommended_actions": ["action 1", "action 2"],
  "confidence": 0.7
}}"""

    def _build_item_explanation_prompt(
        self, item_type: str, item_name: str, context: Dict[str, Any]
    ) -> str:
        """Build a concise prompt for single item risk explanation."""
        type_labels = {
            "permission": "permission Android",
            "activity": "activity",
            "service": "service",
            "receiver": "broadcast receiver",
            "provider": "content provider",
        }
        type_label = type_labels.get(item_type, item_type)
        pkg = context.get('package_name', 'inconnu')

        return f"""Analyse le {type_label} "{item_name}" de l'app {pkg}.

Explique en français: que fait cet élément, quel risque de sécurité il pose, et que recommandes-tu.

JSON:
{{
  "explanation": "[décris le risque concret de {item_name} en 2-3 phrases]",
  "risk_level": "[low, medium, high ou critical]",
  "recommendation": "[une recommandation concrète]"
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

        return f"""Analyse ces {len(incidents)} incidents de sécurité pour détecter des patterns.

{summary}

Cherche: campagnes coordonnées, patterns communs, versions ciblées.

JSON:
{{
  "campaign_detected": false,
  "campaign_type": "[description ou null]",
  "affected_devices": [],
  "pattern_description": "[ton analyse des patterns]",
  "severity": "[low, medium, high ou critical]",
  "recommendations": ["action 1"]
}}"""

    def _build_validation_prompt(
        self, report: Dict, static_score: float, ml_score: float
    ) -> str:
        return f"""Score statique: {static_score:.3f} | Score ML: {ml_score:.3f}
Checks: {json.dumps(report.get('security_checks', {}))}

C'est un vrai positif ou un faux positif? Considère: développeur en debug? utilisateur root? Les features comportementales confirment-elles?

JSON:
{{
  "is_true_positive": true,
  "confidence": 0.7,
  "reasoning": "[ton explication]"
}}"""

    # ── Response Parsing ──

    def _parse_json_response(self, response: str) -> Optional[Dict]:
        """Extract JSON from LLM response, handling various output formats."""
        try:
            result = json.loads(response)
            if isinstance(result, dict):
                explanation = result.get("explanation", "")
                if explanation and self._is_template_text(explanation):
                    print("[LLM] Response is template text, not a real analysis")
                    return None
            return result
        except json.JSONDecodeError:
            pass

        # Fall back to the outermost JSON object embedded in surrounding text
        try:
            start_index = response.find('{')
            end_index = response.rfind('}')

            if start_index != -1 and end_index != -1 and end_index > start_index:
                json_str = response[start_index : end_index + 1]
                result = json.loads(json_str)
                if isinstance(result, dict):
                    explanation = result.get("explanation", "")
                    if explanation and self._is_template_text(explanation):
                        print("[LLM] Extracted JSON is template text")
                        return None
                return result
        except (json.JSONDecodeError, AttributeError):
            pass

        print("[LLM] Failed to parse response as JSON")
        return None

    def _is_template_text(self, text: str) -> bool:
        """Check if the text is just a template placeholder rather than real content."""
        template_markers = [
            "Analyse technique détaillée en FRANÇAIS",
            "RÉDIGE ICI",
            "ÉCRIS un paragraphe",
            "décris le risque concret de",
            "ton analyse des patterns",
            "ton explication",
            "[une valeur parmi",
        ]
        for marker in template_markers:
            if marker in text:
                return True
        return False
