import enum
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, Text, JSON, ForeignKey, Float, UniqueConstraint
from sqlalchemy.orm import relationship, backref
from app.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


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
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class ScanMode(str, enum.Enum):
    ip_sequential = "ip_sequential"
    standard = "standard"


class ScanType(str, enum.Enum):
    one_time = "one_time"
    periodic = "periodic"


class ScanMethod(str, enum.Enum):
    # 注意: nmap_syn 名称暗示 SYN 扫描，但实际是 TCP Connect(-sT)，保留名称仅为向后兼容
    nmap_syn = "nmap_syn"           # TCP Connect 扫描 (Top1000)，命名历史遗留
    nmap_syn_full = "nmap_syn_full" # TCP Connect 全端口扫描
    nmap_connect = "nmap_connect"   # TCP Connect 扫描 (等同 nmap_syn，兼容旧数据)
    nmap_service = "nmap_service"   # 服务版本识别 (-sV)
    nmap_script = "nmap_script"     # 脚本扫描 (-sC)
    nmap_ping = "nmap_ping"         # Ping 主机发现 (-sn)


class ScanCategory(str, enum.Enum):
    host_discovery = "host_discovery"
    service_discovery = "service_discovery"


class ScanTask(Base):
    __tablename__ = "scan_tasks"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    targets = Column(Text, nullable=False)
    scan_category = Column(Enum(ScanCategory), default=ScanCategory.host_discovery, nullable=False)
    scan_type = Column(Enum(ScanType), default=ScanType.one_time, nullable=False)
    scan_mode = Column(Enum(ScanMode), default=ScanMode.standard, nullable=False)
    scan_methods = Column(JSON, default=list)
    ports = Column(String(200), default=None)
    max_concurrent = Column(Integer, default=4)
    interval_hours = Column(Integer, default=72)
    is_active = Column(Boolean, default=True)
    status = Column(Enum(ScanStatus), default=ScanStatus.pending, nullable=False)
    progress = Column(Integer, default=0)
    celery_task_id = Column(String(255), default=None)
    result_summary = Column(JSON, default=dict)
    scan_log = Column(JSON, default=list)
    error_message = Column(Text, default=None)
    last_run = Column(DateTime, default=None)
    next_run = Column(DateTime, default=None)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    started_at = Column(DateTime, default=None)
    completed_at = Column(DateTime, default=None)
    created_at = Column(DateTime, default=_utcnow)

    # --- 服务发现重写：新增字段 ---
    scan_profile_id = Column(Integer, ForeignKey("scan_profiles.id"), nullable=True,
                              comment="关联扫描策略，NULL=旧模式走scan_methods")
    current_phase = Column(String(32), default="",
                           comment="当前阶段: ''=未开始, port_scan, service_and_script, os_detect")
    last_duration_sec = Column(Integer, default=None,
                               comment="上次扫描耗时(秒)，用于智能间隔")

    # --- 关系 ---
    profile = relationship("ScanProfile", backref="tasks", foreign_keys=[scan_profile_id])


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_task_id = Column(Integer, ForeignKey("scan_tasks.id"), nullable=False)
    ip = Column(String(45), nullable=False, index=True)
    mac = Column(String(17), default=None)
    hostname = Column(String(255), default=None)
    os = Column(String(255), default=None)
    os_match = Column(String(255), default=None)  # OS识别详细匹配信息
    ports = Column(JSON, default=list)
    raw_output = Column(Text, default=None)
    created_at = Column(DateTime, default=_utcnow)

    scan_task = relationship("ScanTask", backref="results")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String(45), nullable=False, index=True)
    fingerprint = Column(String(64), unique=True, index=True, nullable=True)
    mac = Column(String(17), default=None)
    hostname = Column(String(255), default=None)
    os = Column(String(255), default=None)
    os_match = Column(String(255), default=None)  # OS识别详细匹配信息
    current_ports = Column(JSON, default=list)
    tags = Column(JSON, default=list)
    group_name = Column(String(100), default=None)
    is_online = Column(Boolean, default=True)
    first_seen = Column(DateTime, default=_utcnow)
    last_seen = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


class AssetSnapshot(Base):
    __tablename__ = "asset_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    scan_task_id = Column(Integer, ForeignKey("scan_tasks.id"), default=None)
    ip = Column(String(45), nullable=False, index=True)
    mac = Column(String(17), default=None)
    hostname = Column(String(255), default=None)
    os = Column(String(255), default=None)
    os_match = Column(String(255), default=None)  # OS识别详细匹配信息
    ports = Column(JSON, default=list)
    created_at = Column(DateTime, default=_utcnow)

    asset = relationship("Asset", backref=backref("snapshots", cascade="all, delete-orphan"))


class ChangeType(str, enum.Enum):
    new_host = "new_host"
    host_down = "host_down"
    new_service = "new_service"
    service_closed = "service_closed"
    version_changed = "version_changed"
    os_changed = "os_changed"
    mac_changed = "mac_changed"
    hostname_changed = "hostname_changed"
    ip_changed = "ip_changed"


class ChangeSeverity(str, enum.Enum):
    info = "info"
    warning = "warning"
    critical = "critical"


class AssetChange(Base):
    __tablename__ = "asset_changes"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    ip = Column(String(45), nullable=False, index=True)
    change_type = Column(Enum(ChangeType), nullable=False)
    detail = Column(JSON, nullable=False)
    snapshot_before_id = Column(Integer, default=None)
    snapshot_after_id = Column(Integer, default=None)
    severity = Column(Enum(ChangeSeverity), default=ChangeSeverity.info)
    detected_at = Column(DateTime, default=_utcnow)

    asset = relationship("Asset", backref=backref("changes", cascade="all, delete-orphan"))


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
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
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)

    asset = relationship("Asset", backref=backref("vulnerabilities", cascade="all, delete-orphan"))


class SystemConfig(Base):
    __tablename__ = "system_config"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, index=True, nullable=False)
    value = Column(Text, nullable=False)
    description = Column(String(255), default=None)
    is_secret = Column(Boolean, default=False)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


class VulnDB(Base):
    __tablename__ = "vuln_db"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(20), nullable=False, index=True)
    cve_description = Column(Text, default=None)
    cvss_score = Column(Float, default=None)
    cvss_version = Column(String(10), default=None)
    severity = Column(String(20), default=None)
    affected_products = Column(JSON, default=list)
    remediation = Column(Text, default=None)
    published_date = Column(DateTime, default=None)
    last_modified = Column(DateTime, default=None)
    fetched_at = Column(DateTime, default=_utcnow)


class ScanChunkStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class ScanChunk(Base):
    __tablename__ = "scan_chunks"

    id = Column(Integer, primary_key=True, index=True)
    scan_task_id = Column(Integer, ForeignKey("scan_tasks.id"), nullable=False, index=True)
    port_start = Column(Integer, nullable=False)
    port_end = Column(Integer, nullable=False)
    status = Column(Enum(ScanChunkStatus), default=ScanChunkStatus.pending, nullable=False)
    retry_count = Column(Integer, default=0)
    open_ports = Column(JSON, default=list)
    error_message = Column(Text, default=None)
    started_at = Column(DateTime, default=None)
    completed_at = Column(DateTime, default=None)

    scan_task = relationship("ScanTask", backref="chunks")


class KnownService(Base):
    __tablename__ = "known_services"

    id = Column(Integer, primary_key=True, index=True)
    port = Column(Integer, nullable=False, index=True)
    proto = Column(String(10), default="tcp", nullable=False)
    name = Column(String(50), nullable=False)
    category = Column(String(50), default="other")
    risk = Column(String(20), default="low")
    description = Column(String(255), default=None)


# ==============================================================================
# 服务发现重写：ScanProfile（扫描策略配置）
# ==============================================================================

class ScanProfile(Base):
    """扫描策略配置表 — 定义渐进式探测的各阶段参数

    核心设计：端口发现(阶段1) → 服务识别(阶段2) → 脚本扫描(阶段3) → OS识别(阶段4)
    每个阶段只对上一阶段发现的开放端口做定向探测，避免重复扫描全端口。
    """
    __tablename__ = "scan_profiles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(String(255), default=None)
    is_default = Column(Boolean, default=False,
                        comment="系统默认策略（新建任务时自动选中）")
    is_builtin = Column(Boolean, default=False,
                        comment="内置策略不可删除，可修改参数")

    # ===== 阶段1: 端口发现（必须执行）=====
    port_scan = Column(JSON, default=dict)
    # {
    #   "mode": "top1000" | "full" | "custom",
    #   "custom_ports": "22,80,443,1-1000",   # mode=custom 时使用
    #   "top_ports": 1000,                     # mode=top1000 时使用
    #   "scan_mode": "standard" | "ip_sequential",
    #   "max_concurrent": 4                    # 并发nmap进程数
    # }

    # ===== 阶段2: 服务版本识别（可选）=====
    service_detect = Column(JSON, default=dict)
    # {
    #   "enabled": true,
    #   "intensity": 7,          # --version-intensity 0-9
    #   "all_ports": false       # --allports
    # }

    # ===== 阶段3: 脚本扫描（可选）=====
    script_scan = Column(JSON, default=dict)
    # {
    #   "enabled": false,
    #   "categories": ["default", "safe"],
    #   "custom_scripts": "",
    #   "script_args": ""
    # }

    # ===== 阶段4: OS识别（可选）=====
    os_detect = Column(JSON, default=dict)
    # {
    #   "enabled": false,
    #   "max_tries": 2,
    #   "scan_guess": false
    # }

    # ===== 通用时序参数 =====
    timing = Column(JSON, default=dict)
    # {
    #   "host_timeout": 300,       # 单主机超时(秒)，0=不限
    #   "nmap_timeout_sec": 7200,  # nmap进程整体超时(秒)，Python层面安全网
    #   "script_timeout_sec": 60,  # 单个NSE脚本超时(秒)
    #   "max_retries": 3,
    #   "min_rate": 300,
    #   "max_rtt_timeout_ms": 500,
    #   "initial_rtt_timeout_ms": 200,
    #   "max_scan_delay_ms": 10,
    #   "phase_executor": "grouped"  # "serial"=逐IP串行, "grouped"=分组并行
    # }
    #
    # ★ 超时层次: script_timeout_sec << host_timeout << nmap_timeout_sec

    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


# ==============================================================================
# 服务发现重写：ScanCheckpoint（断点恢复数据独立表）
# ==============================================================================

class ScanCheckpoint(Base):
    """断点数据独立表 — 按key粒度存储，避免大JSON全量写入

    替代旧方案在 ScanTask 上存 checkpoint JSON 列。
    优势：按key粒度更新，SQLite只写变化的那条记录，而非整个JSON。
    """
    __tablename__ = "scan_checkpoints"

    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(Integer, ForeignKey("scan_tasks.id"), nullable=False, index=True)
    phase = Column(Integer, nullable=False,
                   comment="阶段编号 (1=端口发现, 2=服务识别, 3=脚本扫描, 4=OS识别)")
    key = Column(String(64), nullable=False,
                 comment="键名，如 completed_ips/open_ports/status")
    value = Column(JSON, nullable=True,
                   comment="值（JSON格式，按key粒度更新）")
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        UniqueConstraint("task_id", "phase", "key", name="uq_checkpoint_task_phase_key"),
    )

    scan_task = relationship("ScanTask", backref="checkpoints")
