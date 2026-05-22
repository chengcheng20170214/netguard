import enum
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, Text, JSON, ForeignKey, Float
from sqlalchemy.orm import relationship
from app.database import Base


class UserRole(str, enum.Enum):
    admin = "admin"
    auditor = "auditor"
    guest = "guest"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.auditor, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class ScanMode(str, enum.Enum):
    quick = "quick"
    standard = "standard"
    stealth_light = "stealth_light"
    stealth_medium = "stealth_medium"
    stealth_deep = "stealth_deep"
    custom = "custom"


class ScanMethod(str, enum.Enum):
    nmap_syn = "nmap_syn"
    nmap_connect = "nmap_connect"
    nmap_udp = "nmap_udp"
    nmap_service = "nmap_service"
    nmap_os = "nmap_os"
    nmap_script = "nmap_script"
    masscan = "masscan"
    fping = "fping"
    arp_scan = "arp_scan"


class ScanTask(Base):
    __tablename__ = "scan_tasks"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    targets = Column(Text, nullable=False)
    scan_mode = Column(Enum(ScanMode), default=ScanMode.standard, nullable=False)
    scan_methods = Column(JSON, default=list)
    ports = Column(String(200), default=None)
    status = Column(Enum(ScanStatus), default=ScanStatus.pending, nullable=False)
    progress = Column(Integer, default=0)
    celery_task_id = Column(String(255), default=None)
    result_summary = Column(JSON, default=dict)
    error_message = Column(Text, default=None)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    started_at = Column(DateTime, default=None)
    completed_at = Column(DateTime, default=None)
    created_at = Column(DateTime, default=datetime.utcnow)


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_task_id = Column(Integer, ForeignKey("scan_tasks.id"), nullable=False)
    ip = Column(String(45), nullable=False, index=True)
    mac = Column(String(17), default=None)
    hostname = Column(String(255), default=None)
    os = Column(String(255), default=None)
    ports = Column(JSON, default=list)
    raw_output = Column(Text, default=None)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan_task = relationship("ScanTask", backref="results")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String(45), nullable=False, index=True)
    mac = Column(String(17), default=None)
    hostname = Column(String(255), default=None)
    os = Column(String(255), default=None)
    current_ports = Column(JSON, default=list)
    tags = Column(JSON, default=list)
    group_name = Column(String(100), default=None)
    is_online = Column(Boolean, default=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AssetSnapshot(Base):
    __tablename__ = "asset_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    scan_task_id = Column(Integer, ForeignKey("scan_tasks.id"), default=None)
    ip = Column(String(45), nullable=False, index=True)
    mac = Column(String(17), default=None)
    hostname = Column(String(255), default=None)
    os = Column(String(255), default=None)
    ports = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)

    asset = relationship("Asset", backref="snapshots")


class ChangeType(str, enum.Enum):
    new_host = "new_host"
    host_down = "host_down"
    new_service = "new_service"
    service_closed = "service_closed"
    version_changed = "version_changed"
    os_changed = "os_changed"
    mac_changed = "mac_changed"
    hostname_changed = "hostname_changed"


class ChangeSeverity(str, enum.Enum):
    info = "info"
    warning = "warning"
    critical = "critical"


class AssetChange(Base):
    __tablename__ = "asset_changes"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    ip = Column(String(45), nullable=False, index=True)
    change_type = Column(Enum(ChangeType), nullable=False)
    detail = Column(JSON, nullable=False)
    snapshot_before_id = Column(Integer, default=None)
    snapshot_after_id = Column(Integer, default=None)
    severity = Column(Enum(ChangeSeverity), default=ChangeSeverity.info)
    detected_at = Column(DateTime, default=datetime.utcnow)

    asset = relationship("Asset", backref="changes")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    cve_id = Column(String(20), nullable=False, index=True)
    cve_description = Column(Text, default=None)
    cvss_score = Column(Float, default=None)
    cvss_version = Column(String(10), default=None)
    severity = Column(String(20), default=None)
    affected_service = Column(String(255), default=None)
    affected_version = Column(String(100), default=None)
    remediation = Column(Text, default=None)
    scan_task_id = Column(Integer, ForeignKey("scan_tasks.id"), default=None)
    is_false_positive = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    asset = relationship("Asset", backref="vulnerabilities")


class SystemConfig(Base):
    __tablename__ = "system_config"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, index=True, nullable=False)
    value = Column(Text, nullable=False)
    description = Column(String(255), default=None)
    is_secret = Column(Boolean, default=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
