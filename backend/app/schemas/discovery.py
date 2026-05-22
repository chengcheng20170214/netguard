
from pydantic import BaseModel
from app.models.models import ScanMode, ScanMethod, ScanStatus

class ScanRequest(BaseModel):
    name: str
    targets: str
    scan_mode: ScanMode = ScanMode.standard
    scan_methods: list[ScanMethod] = ["nmap_syn", "nmap_service"]
    ports: str | None = None

class ScanTaskResponse(BaseModel):
    id: int
    name: str
    targets: str
    scan_mode: ScanMode
    scan_methods: list | None = None
    ports: str | None = None
    status: ScanStatus = ScanStatus.pending
    progress: int = 0
    error_message: str | None = None
    created_at: str | None = None
    started_at: str | None = None
    completed_at: str | None = None

    model_config = {"from_attributes": True}

class ScanResultResponse(BaseModel):
    id: int
    scan_task_id: int
    ip: str
    mac: str | None = None
    hostname: str | None = None
    os: str | None = None
    ports: list | None = None
    created_at: str | None = None

    model_config = {"from_attributes": True}
