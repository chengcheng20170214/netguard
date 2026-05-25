from datetime import datetime

from pydantic import BaseModel, field_validator
from app.models.models import ChangeType, ChangeSeverity
import ipaddress

class AssetResponse(BaseModel):
    id: int
    ip: str
    mac: str | None = None
    hostname: str | None = None
    os: str | None = None
    current_ports: list | None = None
    tags: list | None = None
    group_name: str | None = None
    is_online: bool = True
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    model_config = {"from_attributes": True}

class AssetUpdate(BaseModel):
    tags: list | None = None
    group_name: str | None = None

class AssetChangeResponse(BaseModel):
    id: int
    asset_id: int
    ip: str
    change_type: ChangeType
    detail: dict
    severity: ChangeSeverity = ChangeSeverity.info
    detected_at: datetime | None = None

    model_config = {"from_attributes": True}

class AssetSnapshotResponse(BaseModel):
    id: int
    asset_id: int
    ip: str
    mac: str | None = None
    hostname: str | None = None
    os: str | None = None
    ports: list | None = None
    created_at: datetime | None = None

    model_config = {"from_attributes": True}

class AssetImportItem(BaseModel):
    ip: str
    mac: str | None = None
    hostname: str | None = None
    os: str | None = None
    ports: list | None = None
    tags: list | None = None
    group: str | None = None

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v):
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v
