from datetime import datetime
import ipaddress
import re

from pydantic import BaseModel, field_validator
from app.models.models import ScanMode, ScanMethod, ScanStatus, ScanType, ScanCategory

_TARGET_HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$')
_TARGET_RANGE_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$')


def _validate_single_target(t: str) -> str:
    t = t.strip()
    if not t:
        raise ValueError("扫描目标不能为空行")
    try:
        ipaddress.ip_network(t, strict=False)
        return t
    except ValueError:
        pass
    if _TARGET_RANGE_RE.match(t):
        return t
    if _TARGET_HOSTNAME_RE.match(t) and '..' not in t:
        return t
    raise ValueError(f"无效的扫描目标: {t} (支持IP、CIDR、IP范围、域名)")


class ScanRequest(BaseModel):
    name: str
    targets: str
    scan_category: ScanCategory = ScanCategory.host_discovery
    scan_type: ScanType = ScanType.one_time
    scan_mode: ScanMode = ScanMode.standard
    scan_methods: list[ScanMethod] = ["nmap_syn_full", "nmap_service"]
    ports: str | None = None
    max_concurrent: int = 4

    @field_validator("max_concurrent")
    @classmethod
    def validate_max_concurrent(cls, v: int) -> int:
        if v < 1 or v > 16:
            raise ValueError("并发数必须在 1-16 之间")
        return v
    interval_minutes: int | None = None

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, v: str) -> str:
        lines = [line.strip() for line in v.strip().splitlines() if line.strip()]
        if not lines:
            raise ValueError("请至少输入一个扫描目标")
        validated = []
        errors = []
        for i, line in enumerate(lines, 1):
            try:
                validated.append(_validate_single_target(line))
            except ValueError as e:
                errors.append(f"第{i}行: {e}")
        if errors:
            raise ValueError("; ".join(errors))
        return "\n".join(validated)

class ScanUpdateRequest(BaseModel):
    name: str | None = None
    targets: str | None = None
    scan_mode: ScanMode | None = None
    scan_methods: list[ScanMethod] | None = None
    ports: str | None = None
    max_concurrent: int | None = None
    interval_minutes: int | None = None

    @field_validator("max_concurrent")
    @classmethod
    def validate_max_concurrent(cls, v: int | None) -> int | None:
        if v is not None and (v < 1 or v > 16):
            raise ValueError("并发数必须在 1-16 之间")
        return v

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, v: str | None) -> str | None:
        if v is None:
            return v
        lines = [line.strip() for line in v.strip().splitlines() if line.strip()]
        if not lines:
            raise ValueError("请至少输入一个扫描目标")
        validated = []
        errors = []
        for i, line in enumerate(lines, 1):
            try:
                validated.append(_validate_single_target(line))
            except ValueError as e:
                errors.append(f"第{i}行: {e}")
        if errors:
            raise ValueError("; ".join(errors))
        return "\n".join(validated)

    @field_validator("interval_minutes")
    @classmethod
    def validate_interval(cls, v: int | None) -> int | None:
        if v is not None and v < 1:
            raise ValueError("周期扫描间隔必须大于0分钟")
        return v


class ScanTaskResponse(BaseModel):
    id: int
    name: str
    targets: str
    scan_category: ScanCategory = ScanCategory.host_discovery
    scan_type: ScanType = ScanType.one_time
    scan_mode: ScanMode
    scan_methods: list | None = None
    ports: str | None = None
    max_concurrent: int = 4
    interval_minutes: int | None = None
    is_active: bool = True
    status: ScanStatus = ScanStatus.pending
    progress: int = 0
    error_message: str | None = None
    scan_log: list | None = None
    last_run: datetime | None = None
    next_run: datetime | None = None
    created_at: datetime | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None

    model_config = {"from_attributes": True}

class ScanResultResponse(BaseModel):
    id: int
    scan_task_id: int
    ip: str
    mac: str | None = None
    hostname: str | None = None
    os: str | None = None
    ports: list | None = None
    created_at: datetime | None = None

    model_config = {"from_attributes": True}
