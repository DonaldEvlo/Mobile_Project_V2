import enum
from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime,
    Text, Enum as SAEnum, JSON
)
from app.core.database import Base


class ThreatLevelEnum(str, enum.Enum):
    clean = "clean"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class SecurityReportModel(Base):
    """ORM model for security reports received from mobile clients."""

    __tablename__ = "security_reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(64), nullable=False, index=True)
    app_version = Column(String(20), nullable=True)
    platform = Column(String(10), nullable=True)
    os_version = Column(String(20), nullable=True)

    # Security check results (JSON blob)
    security_checks = Column(JSON, nullable=False)

    # Behavioral features (JSON blob)
    behavior_features = Column(JSON, nullable=False)

    # Scoring
    static_score = Column(Float, nullable=False, default=0.0)
    ml_score = Column(Float, nullable=False, default=0.0)
    combined_score = Column(Float, nullable=False, default=0.0)

    # Local (mobile-side) analysis results
    local_anomaly_score = Column(Float, nullable=True)
    local_threat_level = Column(String(20), nullable=True)

    # Backend analysis results
    threat_level = Column(SAEnum(ThreatLevelEnum), nullable=False, default=ThreatLevelEnum.clean)
    attack_type = Column(String(50), nullable=True)

    # LLM analysis (populated async)
    llm_analysis = Column(Text, nullable=True)
    llm_false_positive_probability = Column(Float, nullable=True)

    # Action taken
    action_taken = Column(String(50), nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    analyzed_at = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self):
        return f"<SecurityReport(id={self.id}, device={self.device_id}, level={self.threat_level})>"
