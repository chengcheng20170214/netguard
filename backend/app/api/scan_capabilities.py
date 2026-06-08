"""扫描能力检测 API

检测当前运行环境下 nmap 的能力：
  - nmap 可用性 & 版本
  - OS 识别(-O) 是否可用（需要 root 权限）
  - sudo 提权配置管理（加密存储 sudo 密码）
"""

import asyncio
import logging
import os
import subprocess

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db, async_session
from app.middleware.auth import require_role
from app.models.models import SystemConfig, User, UserRole
from app.config import settings, ensure_encrypt_key

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scan", tags=["扫描能力"])

# SystemConfig 中存储 sudo 密码的 key
_SUDO_PASSWORD_KEY = "sudo_password_encrypted"


# ─── Pydantic Schema ──────────────────────────────────────────

class CapabilitiesResponse(BaseModel):
    """扫描能力检测结果"""
    nmap_available: bool = False
    nmap_version: str | None = None
    os_detect_available: bool = False
    os_detect_reason: str | None = None  # 不可用时的原因
    sudo_configured: bool = False         # sudo 密码是否已配置
    sudo_enabled: bool = False            # NMAP_SUDO_ENABLED 是否开启


class SudoPasswordRequest(BaseModel):
    """设置 sudo 密码请求"""
    password: str = Field(..., min_length=1, max_length=256, description="sudo 密码")


class SudoVerifyResponse(BaseModel):
    """sudo 密码验证结果"""
    valid: bool
    message: str


# ─── 检测逻辑 ─────────────────────────────────────────────────

def _check_nmap_available() -> tuple[bool, str | None]:
    """检测 nmap 是否可用，返回 (可用, 版本号)"""
    try:
        result = subprocess.run(
            [settings.NMAP_PATH, "--version"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            # 解析版本号，如 "Nmap version 7.95 ( https://nmap.org )"
            for line in result.stdout.splitlines():
                if "Nmap version" in line:
                    version = line.split("Nmap version")[1].strip().split()[0]
                    return True, version
            return True, "unknown"
        return False, None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False, None


def _check_root_privilege() -> tuple[bool, str | None]:
    """检测当前进程是否有 root 权限"""
    try:
        if os.geteuid() == 0:
            return True, None
    except AttributeError:
        pass  # 非 Unix 系统
    return False, "需要 root 权限"


def _check_sudo_with_password(password: str) -> tuple[bool, str]:
    """验证 sudo 密码是否正确（不保存，仅验证）

    Returns:
        (是否成功, 消息)
    """
    try:
        proc = subprocess.run(
            ["sudo", "-S", "-v"],  # -v: 验证 sudo 凭证
            input=password + "\n",
            capture_output=True, text=True, timeout=15,
        )
        if proc.returncode == 0:
            return True, "sudo 密码验证成功"
        else:
            stderr = proc.stderr.strip()
            if "incorrect password" in stderr.lower() or "sorry" in stderr.lower():
                return False, "sudo 密码错误"
            return False, f"sudo 验证失败: {stderr}"
    except FileNotFoundError:
        return False, "系统未安装 sudo"
    except subprocess.TimeoutExpired:
        return False, "sudo 验证超时"
    except Exception as e:
        return False, f"sudo 验证异常: {e}"


async def _get_sudo_password_encrypted(db: AsyncSession) -> str | None:
    """从数据库读取加密的 sudo 密码"""
    result = await db.execute(
        select(SystemConfig).where(SystemConfig.key == _SUDO_PASSWORD_KEY)
    )
    entry = result.scalar_one_or_none()
    return entry.value if entry else None


async def _save_sudo_password_encrypted(db: AsyncSession, encrypted: str):
    """保存加密后的 sudo 密码到数据库"""
    result = await db.execute(
        select(SystemConfig).where(SystemConfig.key == _SUDO_PASSWORD_KEY)
    )
    entry = result.scalar_one_or_none()
    if entry:
        entry.value = encrypted
        entry.is_secret = True
    else:
        entry = SystemConfig(
            key=_SUDO_PASSWORD_KEY,
            value=encrypted,
            description="加密存储的 sudo 密码（用于 nmap 提权执行 OS 识别）",
            is_secret=True,
        )
        db.add(entry)
    await db.commit()


async def _delete_sudo_password(db: AsyncSession):
    """删除存储的 sudo 密码"""
    result = await db.execute(
        select(SystemConfig).where(SystemConfig.key == _SUDO_PASSWORD_KEY)
    )
    entry = result.scalar_one_or_none()
    if entry:
        await db.delete(entry)
        await db.commit()


def decrypt_sudo_password(encrypted: str) -> str | None:
    """解密 sudo 密码（供 nmap 执行器调用）

    Args:
        encrypted: 数据库中存储的加密密码

    Returns:
        解密后的密码明文，失败返回 None
    """
    try:
        from app.utils.crypto import decrypt, clear_memory
        encrypt_key = ensure_encrypt_key()
        return decrypt(encrypted, encrypt_key)
    except Exception as e:
        logger.error(f"解密 sudo 密码失败: {e}")
        return None


# ─── API 端点 ─────────────────────────────────────────────────

@router.get("/capabilities", response_model=CapabilitiesResponse)
async def get_capabilities(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    """检测当前环境扫描能力

    仅管理员可访问。返回 nmap 可用性、OS 识别能力、sudo 配置状态。
    """
    # 1. nmap 可用性
    nmap_available, nmap_version = _check_nmap_available()

    # 2. root 权限检测
    is_root, _ = _check_root_privilege()

    # 3. sudo 密码配置检测
    sudo_pwd_encrypted = await _get_sudo_password_encrypted(db)
    sudo_configured = sudo_pwd_encrypted is not None

    # 4. OS 识别能力判断
    sudo_enabled = settings.NMAP_SUDO_ENABLED
    if is_root:
        os_detect_available = True
        os_detect_reason = None
    elif sudo_enabled and sudo_configured:
        # sudo 已配置密码且已启用，假定可用（实际验证在扫描时做）
        os_detect_available = True
        os_detect_reason = None
    else:
        os_detect_available = False
        if not is_root:
            if not sudo_enabled:
                os_detect_reason = "需要 root 权限，可通过配置 sudo 密码提权"
            elif not sudo_configured:
                os_detect_reason = "需要 root 权限，sudo 已启用但未配置密码"
            else:
                os_detect_reason = "需要 root 权限"

    return CapabilitiesResponse(
        nmap_available=nmap_available,
        nmap_version=nmap_version,
        os_detect_available=os_detect_available,
        os_detect_reason=os_detect_reason,
        sudo_configured=sudo_configured,
        sudo_enabled=sudo_enabled,
    )


@router.put("/capabilities/sudo-password")
async def set_sudo_password(
    req: SudoPasswordRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    """设置 sudo 密码（加密存储）

    先验证密码正确性，再加密存储。
    """
    # 1. 先验证密码是否正确
    valid, msg = await asyncio.to_thread(_check_sudo_with_password, req.password)
    if not valid:
        raise HTTPException(status_code=400, detail=f"sudo 密码验证失败: {msg}")

    # 2. 加密存储
    try:
        from app.utils.crypto import encrypt
        encrypt_key = ensure_encrypt_key()
        encrypted = encrypt(req.password, encrypt_key)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"加密失败: {e}")

    await _save_sudo_password_encrypted(db, encrypted)

    # 3. 自动启用 NMAP_SUDO_ENABLED
    if not settings.NMAP_SUDO_ENABLED:
        settings.NMAP_SUDO_ENABLED = True
        # 同步写入 .env
        _update_env_flag("NMAP_SUDO_ENABLED", "true")

    return {"message": "sudo 密码已设置并验证通过", "sudo_enabled": True}


@router.delete("/capabilities/sudo-password")
async def remove_sudo_password(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    """删除已存储的 sudo 密码"""
    await _delete_sudo_password(db)

    # 同时禁用 NMAP_SUDO_ENABLED
    if settings.NMAP_SUDO_ENABLED:
        settings.NMAP_SUDO_ENABLED = False
        _update_env_flag("NMAP_SUDO_ENABLED", "false")

    return {"message": "sudo 密码已删除，sudo 提权已禁用"}


@router.post("/capabilities/verify-sudo", response_model=SudoVerifyResponse)
async def verify_sudo_password(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    """验证已存储的 sudo 密码是否仍然有效

    用于定期检查密码是否被修改。
    """
    encrypted = await _get_sudo_password_encrypted(db)
    if not encrypted:
        return SudoVerifyResponse(valid=False, message="未配置 sudo 密码")

    password = decrypt_sudo_password(encrypted)
    if not password:
        return SudoVerifyResponse(valid=False, message="sudo 密码解密失败，可能 ENCRYPT_KEY 已变更")

    valid, msg = await asyncio.to_thread(_check_sudo_with_password, password)
    return SudoVerifyResponse(valid=valid, message=msg)


@router.put("/capabilities/sudo-enabled")
async def toggle_sudo_enabled(
    enabled: bool,
    current_user: User = Depends(require_role(UserRole.admin)),
):
    """启用/禁用 sudo 提权（不删除密码）"""
    settings.NMAP_SUDO_ENABLED = enabled
    _update_env_flag("NMAP_SUDO_ENABLED", "true" if enabled else "false")
    return {
        "message": f"sudo 提权已{'启用' if enabled else '禁用'}",
        "sudo_enabled": enabled,
    }


def _update_env_flag(key: str, value: str):
    """更新 .env 中的标志位"""
    env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
    try:
        lines = []
        if os.path.exists(env_path):
            with open(env_path, "r") as f:
                lines = f.readlines()

        found = False
        for i, line in enumerate(lines):
            if line.strip().startswith(f"{key}="):
                lines[i] = f"{key}={value}\n"
                found = True
                break

        if not found:
            if lines and not lines[-1].endswith("\n"):
                lines[-1] += "\n"
            lines.append(f"{key}={value}\n")

        with open(env_path, "w") as f:
            f.writelines(lines)
    except Exception as e:
        logger.warning(f"无法写入 {key} 到 .env: {e}")
