import httpx
from typing import Optional

from app.core.config import get_settings

settings = get_settings()


class AlertService:
    """
    Sends critical alerts to Slack and SIEM webhooks.

    Triggered asynchronously when threat_level == 'critical'.
    """

    async def send_critical_alert(
        self,
        device_id: str,
        score: float,
        attack_type: Optional[str] = None,
    ):
        """Send critical threat alert to all configured channels."""
        message = self._build_alert_message(device_id, score, attack_type)

        # Send to Slack
        if settings.SLACK_WEBHOOK_URL:
            await self._send_slack(message)

        # Send to SIEM
        if settings.SIEM_WEBHOOK_URL:
            await self._send_siem(device_id, score, attack_type)

        print(f"[ALERT] Critical alert sent for device {device_id} (score: {score})")

    async def _send_slack(self, message: str):
        """Send alert to Slack webhook."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(
                    settings.SLACK_WEBHOOK_URL,
                    json={
                        "text": message,
                        "username": "Security Monitor",
                        "icon_emoji": ":shield:",
                    },
                )
        except Exception as e:
            print(f"[ALERT] Slack notification failed: {e}")

    async def _send_siem(
        self,
        device_id: str,
        score: float,
        attack_type: Optional[str],
    ):
        """Send structured alert to SIEM webhook (Splunk, Elastic, etc.)."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(
                    settings.SIEM_WEBHOOK_URL,
                    json={
                        "event_type": "mobile_security_critical",
                        "severity": "critical",
                        "device_id": device_id,
                        "combined_score": score,
                        "attack_type": attack_type,
                        "source": "anti-tampering-api",
                        "action_taken": "force_logout",
                    },
                )
        except Exception as e:
            print(f"[ALERT] SIEM notification failed: {e}")

    def _build_alert_message(
        self,
        device_id: str,
        score: float,
        attack_type: Optional[str],
    ) -> str:
        """Build a human-readable alert message."""
        attack_str = f" ({attack_type})" if attack_type else ""
        return (
            f"🚨 *CRITICAL SECURITY ALERT*\n\n"
            f"*Device:* `{device_id}`\n"
            f"*Combined Score:* `{score:.3f}`\n"
            f"*Attack Type:* `{attack_type or 'Unknown'}`{attack_str}\n"
            f"*Action Taken:* Force logout + token revocation\n\n"
            f"Immediate investigation required."
        )
