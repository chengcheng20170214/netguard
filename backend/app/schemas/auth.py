
from datetime import datetime
from pydantic import BaseModel, field_validator
from app.models.models import UserRole

class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    role: UserRole = UserRole.auditor

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v):
        if len(v) < 15:
            raise ValueError("密码长度不得少于15位")
        return v

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "bearer"

class RefreshRequest(BaseModel):
    refresh_token: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime | None = None

    model_config = {"from_attributes": True}
