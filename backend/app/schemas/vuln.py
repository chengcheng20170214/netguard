
from pydantic import BaseModel

class VulnerabilityResponse(BaseModel):
    id: int
    asset_id: int
    cve_id: str
    cve_description: str | None = None
    cvss_score: float | None = None
    severity: str | None = None
    affected_service: str | None = None
    affected_version: str | None = None
    remediation: str | None = None
    is_false_positive: bool = False
    created_at: str | None = None

    model_config = {"from_attributes": True}

class VulnScanRequest(BaseModel):
    asset_id: int
    scan_task_id: int | None = None
