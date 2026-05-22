from pydantic import BaseModel

class ConfigItem(BaseModel):
    key: str
    value: str
    description: str | None = None
    is_secret: bool = False

class ConfigUpdate(BaseModel):
    value: str

class ConfigResponse(BaseModel):
    key: str
    value: str
    description: str | None = None
    is_secret: bool = False
    updated_at: str | None = None

    model_config = {"from_attributes": True}
