import json
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, Query
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.security_report import SecurityReportModel, ThreatLevelEnum

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/incidents")
async def get_recent_incidents(
    limit: int = Query(default=20, le=100),
    threat_level: str = Query(default=None),
    device_id: str = Query(default=None),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Get recent security incidents with optional filtering."""
    query = select(SecurityReportModel).order_by(desc(SecurityReportModel.created_at))

    if threat_level:
        query = query.where(SecurityReportModel.threat_level == ThreatLevelEnum(threat_level))
    if device_id:
        query = query.where(SecurityReportModel.device_id == device_id)

    query = query.limit(limit)
    result = await db.execute(query)
    reports = result.scalars().all()

    return {
        "count": len(reports),
        "incidents": [
            {
                "id": r.id,
                "device_id": r.device_id,
                "threat_level": r.threat_level.value if r.threat_level else "clean",
                "combined_score": r.combined_score,
                "static_score": r.static_score,
                "ml_score": r.ml_score,
                "attack_type": r.attack_type,
                "action_taken": r.action_taken,
                "llm_analysis": r.llm_analysis,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in reports
        ],
    }


@router.get("/stats")
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Get aggregate statistics for the security dashboard."""
    total_result = await db.execute(select(func.count(SecurityReportModel.id)))
    total_reports = total_result.scalar() or 0

    level_counts = {}
    for level in ThreatLevelEnum:
        count_result = await db.execute(
            select(func.count(SecurityReportModel.id))
            .where(SecurityReportModel.threat_level == level)
        )
        level_counts[level.value] = count_result.scalar() or 0

    avg_result = await db.execute(
        select(func.avg(SecurityReportModel.combined_score))
    )
    avg_score = avg_result.scalar() or 0.0

    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    critical_result = await db.execute(
        select(func.count(SecurityReportModel.id))
        .where(SecurityReportModel.threat_level == ThreatLevelEnum.critical)
        .where(SecurityReportModel.created_at >= cutoff)
    )
    critical_24h = critical_result.scalar() or 0

    return {
        "total_reports": total_reports,
        "threat_distribution": level_counts,
        "average_score": round(float(avg_score), 3),
        "critical_last_24h": critical_24h,
    }


@router.websocket("/ws/incidents")
async def websocket_incidents(websocket: WebSocket):
    """
    WebSocket endpoint for real-time incident streaming.

    Clients connect and receive new incidents as they arrive.
    In production, this would be backed by Redis pub/sub.
    """
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_json({
                "type": "ack",
                "message": f"Received: {data}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
    except WebSocketDisconnect:
        pass
