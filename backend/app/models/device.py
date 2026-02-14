from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime
from app.core.database import Base


class DeviceModel(Base):
    """ORM model for device fingerprints and history tracking."""

    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(64), unique=True, nullable=False, index=True)
    platform = Column(String(10), nullable=True)
    os_version = Column(String(20), nullable=True)
    app_version = Column(String(20), nullable=True)
    model = Column(String(100), nullable=True)
    manufacturer = Column(String(100), nullable=True)

    # Tracking
    total_reports = Column(Integer, default=0)
    total_threats = Column(Integer, default=0)
    highest_threat_level = Column(String(20), default="clean")

    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    def __repr__(self):
        return f"<Device(id={self.device_id}, threats={self.total_threats})>"
