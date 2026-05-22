
from pydantic import BaseModel
from app.models.models import ChangeType, ChangeSeverity

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
    first_seen: str | None = None
    last_seen: str | None = None

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
    detected_at: str | None = None

    model_config = {"from_attributes": True}

class AssetSnapshotResponse(BaseModel):
    id: int
    asset_id: int
    ip: str
    mac: str | None = None
    hostname: str | None = None
    os: str | None = None
    ports: list | None = None
    created_at: str | None = None

    model_config = {"from_attributes": True}
