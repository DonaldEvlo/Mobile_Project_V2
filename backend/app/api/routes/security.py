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


@router.get("/health")
async def health_check():
    """Check backend and Ollama/Qwen connectivity."""
    llm_status = "unknown"
    llm_model = settings.OLLAMA_MODEL
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{settings.OLLAMA_URL}/api/tags")
            if resp.status_code == 200:
                llm_status = "connected"
            else:
                llm_status = "error"
    except Exception:
        llm_status = "unreachable"

    return {
        "status": "ok",
        "llm_status": llm_status,
        "llm_model": llm_model,
        "llm_url": settings.OLLAMA_URL,
    }


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


class ApkAuditPayload(BaseModel):
    package_name: str
    version: str
    apk_hash: str
    installer_source: Optional[str] = None
    is_sideloaded: bool = False
    is_debuggable: bool = False
    sensitive_permissions_count: int = 0
    sensitive_permissions: list[str] = []
    permissions: list[str] = []
    activities: list[str] = []
    services: list[str] = []
    receivers: list[str] = []
    providers: list[str] = []
    is_valid: bool = True


class SecurityReportResponse(BaseModel):
    threat_level: str
    score: float
    action: Optional[str] = None
    message: Optional[str] = None
    attack_type: Optional[str] = None
    llm_analysis: Optional[str] = None


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
    wait_for_llm: bool = False,
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
    # ── Step 5: Background tasks OR Immediate LLM ──
    llm_result_text = None
    
    if threat_level in ("medium", "high", "critical"):
        if wait_for_llm:
            # Run immediately and return result
            try:
                analysis = await ollama_analyzer.analyze_incident(payload.model_dump(), threat_level)
                if analysis:
                    llm_result_text = analysis.get("explanation", "")
                    
                    # Update report in DB
                    report.llm_analysis = llm_result_text
                    report.llm_false_positive_probability = analysis.get("false_positive_probability")
                    report.analyzed_at = datetime.now(timezone.utc)
                    db.add(report)
                    await db.commit()
            except Exception as e:
                print(f"Immediate LLM enrichment failed: {e}")
        else:
            # Run in background
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
        llm_analysis=llm_result_text,
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


@router.post("/apk-analysis", response_model=SecurityReportResponse)
async def analyze_apk(
    payload: ApkAuditPayload,
    db: AsyncSession = Depends(get_db),
):
    """
    Analyze specific APK details using LLM and static rules.
    """
    # 1. Base Score Calculation
    score = 0.0
    
    if not payload.is_valid:
        score += 0.8  # Invalid APK is very suspicious
    
    if payload.is_debuggable:
        score += 0.9  # Debuggable in prod is critical risk
        
    if payload.is_sideloaded:
        score += 0.4  # Sideloading is risky but common
        
    # Permission risk
    if payload.sensitive_permissions_count > 5:
        score += 0.3
    if payload.sensitive_permissions_count > 10:
        score += 0.3

    score = min(score, 1.0)
    threat_level = _score_to_level(score)

    # 2. LLM Analysis
    llm_explanation = None
    try:
        # Construct a prompt context for the LLM
        context = {
            "task": "APK_ANALYSIS",
            "instruction": (
                "PROVIDE A DETAILED SECURITY ASSESSMENT of this APK. "
                "Analyze EVERY permission listed and explain its risk. "
                "Examine the declared Activities, Services, BroadcastReceivers, and ContentProviders for suspicious patterns. "
                "Explain risks of debuggable builds and side-loading. "
                "Provide concrete, actionable recommendations."
            ),
            "package_name": payload.package_name,
            "version": payload.version,
            "apk_hash": payload.apk_hash,
            "installer": payload.installer_source,
            "sideloaded": payload.is_sideloaded,
            "debuggable": payload.is_debuggable,
            "all_permissions": payload.permissions,
            "sensitive_permissions": payload.sensitive_permissions,
            "sensitive_permissions_count": payload.sensitive_permissions_count,
            "activities": payload.activities,
            "services": payload.services,
            "receivers": payload.receivers,
            "providers": payload.providers,
        }
        
        # We reuse the analyzer but with a custom prompt focus
        llm_result = await ollama_analyzer.analyze_incident(context, threat_level)
        print(f"[DEBUG] Analyze APK LLM Result: {llm_result is not None}")
        if llm_result:
            llm_explanation = llm_result.get("explanation")
    except Exception as e:
        print(f"LLM Analysis failed: {e}")
        llm_explanation = "Analyse cloud impossible (Service IA indisponible)."

    message = f"Analysis complete. Risk: {threat_level.upper()}"
    if payload.is_debuggable:
        message = "CRITICAL: Debuggable APK detected."

    return SecurityReportResponse(
        threat_level=threat_level,
        score=round(score, 3),
        action="block" if score > 0.8 else "warn",
        message=message,
        attack_type="malicious_apk" if score > 0.7 else None,
        llm_analysis=llm_explanation,
    )


# ── Per-Item AI Risk Explanation ──

class ExplainRiskPayload(BaseModel):
    item_type: str  # 'permission', 'activity', 'service', 'receiver', 'provider'
    item_name: str
    context: dict = {}  # package_name, all_permissions, activities, services, etc.


class ExplainRiskResponse(BaseModel):
    explanation: str
    risk_level: str = "unknown"
    recommendation: str = ""


@router.post("/explain-risk", response_model=ExplainRiskResponse)
async def explain_risk(payload: ExplainRiskPayload):
    """
    Get an AI-generated risk explanation for a single APK item
    (permission, activity, service, receiver, or provider).
    """
    try:
        result = await ollama_analyzer.explain_single_item(
            item_type=payload.item_type,
            item_name=payload.item_name,
            context=payload.context,
        )

        if result:
            return ExplainRiskResponse(
                explanation=result.get("explanation", "Aucune explication disponible."),
                risk_level=result.get("risk_level", "unknown"),
                recommendation=result.get("recommendation", ""),
            )
    except Exception as e:
        print(f"[explain-risk] LLM error: {e}")

    return ExplainRiskResponse(
        explanation="Analyse IA indisponible. Le service Qwen n'a pas pu générer d'explication.",
        risk_level="unknown",
        recommendation="Vérifiez la documentation officielle Android pour plus de détails.",
    )


