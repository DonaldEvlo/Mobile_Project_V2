from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_optional_user
from app.core.config import get_settings
from app.models.security_report import SecurityReportModel, ThreatLevelEnum
from app.models.device import DeviceModel
from app.ml.anomaly_detector import AnomalyDetector
from app.services.threat_analyzer import ThreatAnalyzer
from app.services.alert_service import AlertService
from app.services.llm_analyzer import OllamaAnalyzer

router = APIRouter(prefix="/api/security", tags=["Security"])
settings = get_settings()

# ── Singletons ──
anomaly_detector = AnomalyDetector()
threat_analyzer = ThreatAnalyzer()
alert_service = AlertService()
ollama_analyzer = OllamaAnalyzer()


# ── Request/Response schemas ──

class SecurityChecksPayload(BaseModel):
    frida_detected: bool = False
    root_detected: bool = False
    signature_valid: bool = True
    dex_integrity_valid: bool = True
    xposed_detected: bool = False
    debugger_attached: bool = False
    emulator_detected: bool = False
    hook_detected: bool = False
    cert_pinning_bypassed: bool = False


class BehaviorFeaturesPayload(BaseModel):
    network_calls_count: float = 0
    file_access_count: float = 0
    timing_entropy: float = 0.5
    api_call_sequence_hash: float = 0
    memory_anomaly_score: float = 0
    cpu_spike_count: float = 0


class SecurityReportPayload(BaseModel):
    device_id: str = Field(..., min_length=1, max_length=64)
    app_version: Optional[str] = None
    platform: Optional[str] = None
    os_version: Optional[str] = None
    security_checks: SecurityChecksPayload
    behavior_features: BehaviorFeaturesPayload
    local_anomaly_score: Optional[float] = None
    local_threat_level: Optional[str] = None
    timestamp: Optional[str] = None


class SecurityReportResponse(BaseModel):
    threat_level: str
    score: float
    action: Optional[str] = None
    message: Optional[str] = None
    attack_type: Optional[str] = None


def _score_to_level(score: float) -> str:
    """Convert a combined score to a threat level string."""
    if score > settings.THRESHOLD_CRITICAL:
        return "critical"
    elif score > settings.THRESHOLD_HIGH:
        return "high"
    elif score > settings.THRESHOLD_MEDIUM:
        return "medium"
    elif score > settings.THRESHOLD_LOW:
        return "low"
    return "clean"


async def _enrich_with_llm(report_id: int, payload: dict, threat_level: str, db: AsyncSession):
    """Background task: enrich security report with LLM analysis."""
    try:
        analysis = await ollama_analyzer.analyze_incident(payload, threat_level)
        if analysis:
            from sqlalchemy import update
            stmt = (
                update(SecurityReportModel)
                .where(SecurityReportModel.id == report_id)
                .values(
                    llm_analysis=analysis.get("explanation", ""),
                    llm_false_positive_probability=analysis.get("false_positive_probability"),
                    analyzed_at=datetime.now(timezone.utc),
                )
            )
            await db.execute(stmt)
            await db.commit()
    except Exception as e:
        print(f"LLM enrichment failed: {e}")


@router.post("/report", response_model=SecurityReportResponse)
async def receive_security_report(
    payload: SecurityReportPayload,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    user: Optional[dict] = Depends(get_optional_user),
):
    """
    Main security report endpoint.

    Pipeline:
    1. Static analysis (deterministic, weighted checks)
    2. ML anomaly detection (Isolation Forest)
    3. Combined scoring (60% static + 40% ML)
    4. LLM enrichment (background, for medium+ threats)
    5. Critical alerting (background)
    """

    # ── Step 1: Static Analysis ──
    checks_dict = payload.security_checks.model_dump()
    static_result = threat_analyzer.analyze_static(checks_dict)

    # ── Step 2: ML Scoring ──
    features = payload.behavior_features.model_dump()
    features_vector = [
        features["network_calls_count"],
        features["file_access_count"],
        features["timing_entropy"],
        features["api_call_sequence_hash"],
        features["memory_anomaly_score"],
        features["cpu_spike_count"],
    ]
    ml_score, attack_type = anomaly_detector.predict(features_vector)

    # ── Step 3: Combined Score ──
    combined_score = (static_result["score"] * settings.STATIC_WEIGHT) + (ml_score * settings.ML_WEIGHT)
    threat_level = _score_to_level(combined_score)

    # Determine action
    action = None
    message = None
    if threat_level == "critical":
        action = "force_logout"
        message = "Critical threat detected — session terminated"
    elif threat_level == "high":
        message = "High threat level — enhanced monitoring activated"

    # Use attack type from static if none from ML
    final_attack_type = attack_type or static_result.get("attack_indicators", [None])[0] if static_result.get("attack_indicators") else attack_type

    # ── Step 4: Persist to database ──
    report = SecurityReportModel(
        device_id=payload.device_id,
        app_version=payload.app_version,
        platform=payload.platform,
        os_version=payload.os_version,
        security_checks=checks_dict,
        behavior_features=features,
        static_score=static_result["score"],
        ml_score=ml_score,
        combined_score=combined_score,
        local_anomaly_score=payload.local_anomaly_score,
        local_threat_level=payload.local_threat_level,
        threat_level=ThreatLevelEnum(threat_level),
        attack_type=final_attack_type,
        action_taken=action,
    )
    db.add(report)
    await db.flush()

    # Update device record
    await _update_device(db, payload, threat_level)

    # ── Step 5: Background tasks ──
    if threat_level in ("medium", "high", "critical"):
        background_tasks.add_task(
            _enrich_with_llm,
            report.id,
            payload.model_dump(),
            threat_level,
            db,
        )

    if threat_level == "critical":
        background_tasks.add_task(
            alert_service.send_critical_alert,
            payload.device_id,
            combined_score,
            final_attack_type,
        )

    return SecurityReportResponse(
        threat_level=threat_level,
        score=round(combined_score, 3),
        action=action,
        message=message,
        attack_type=final_attack_type,
    )


async def _update_device(db: AsyncSession, payload: SecurityReportPayload, threat_level: str):
    """Update or create device tracking record."""
    from sqlalchemy import select

    result = await db.execute(
        select(DeviceModel).where(DeviceModel.device_id == payload.device_id)
    )
    device = result.scalar_one_or_none()

    if device:
        device.last_seen = datetime.now(timezone.utc)
        device.total_reports += 1
        if threat_level not in ("clean", "low"):
            device.total_threats += 1
        # Update highest threat level
        level_order = {"clean": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        if level_order.get(threat_level, 0) > level_order.get(device.highest_threat_level, 0):
            device.highest_threat_level = threat_level
    else:
        device = DeviceModel(
            device_id=payload.device_id,
            platform=payload.platform,
            os_version=payload.os_version,
            app_version=payload.app_version,
            total_reports=1,
            total_threats=1 if threat_level not in ("clean", "low") else 0,
            highest_threat_level=threat_level,
        )
        db.add(device)
