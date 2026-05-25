from datetime import datetime

from pydantic import BaseModel
from app.models.models import ScanMode, ScanMethod, ScanStatus, ScanType

class ScanRequest(BaseModel):
    name: str
    targets: str
    scan_type: ScanType = ScanType.one_time
    scan_mode: ScanMode = ScanMode.standard
    scan_methods: list[ScanMethod] = ["nmap_syn", "nmap_service"]
    ports: str | None = None
    interval_minutes: int | None = None

class ScanTaskResponse(BaseModel):
    id: int
    name: str
    targets: str
    scan_type: ScanType = ScanType.one_time
    scan_mode: ScanMode
    scan_methods: list | None = None
    ports: str | None = None
    interval_minutes: int | None = None
    is_active: bool = True
    status: ScanStatus = ScanStatus.pending
    progress: int = 0
    error_message: str | None = None
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
