"""扫描策略 (ScanProfile) CRUD API

对应设计文档 §5.1/§5.2，提供策略的增删改查接口。

端点：
  GET    /api/scan-profiles          — 列表（支持 brief 模式用于下拉）
  POST   /api/scan-profiles          — 创建
  GET    /api/scan-profiles/{id}     — 详情
  PUT    /api/scan-profiles/{id}     — 更新
  DELETE /api/scan-profiles/{id}     — 删除（内置策略不可删除）
  PUT    /api/scan-profiles/{id}/default — 设为默认策略
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.models import ScanProfile, ScanTask
from app.schemas.profile import (
    ScanProfileCreate,
    ScanProfileUpdate,
    ScanProfileResponse,
    ScanProfileBrief,
)

router = APIRouter(prefix="/api/scan-profiles", tags=["扫描策略"])


# ──────────────────────────────────────────────────────────
# 辅助函数
# ──────────────────────────────────────────────────────────

async def _get_profile_or_404(db: AsyncSession, profile_id: int) -> ScanProfile:
    """根据ID获取策略，不存在则404"""
    result = await db.execute(select(ScanProfile).where(ScanProfile.id == profile_id))
    profile = result.scalar_one_or_none()
    if not profile:
        raise HTTPException(status_code=404, detail=f"扫描策略 #{profile_id} 不存在")
    return profile


def _profile_to_response(profile: ScanProfile) -> ScanProfileResponse:
    """ORM 对象转响应模型"""
    return ScanProfileResponse(
        id=profile.id,
        name=profile.name,
        description=profile.description,
        is_default=profile.is_default,
        is_builtin=profile.is_builtin,
        port_scan=profile.port_scan or {},
        service_detect=profile.service_detect or {},
        script_scan=profile.script_scan or {},
        os_detect=profile.os_detect or {},
        timing=profile.timing or {},
        created_at=profile.created_at.isoformat() if profile.created_at else None,
        updated_at=profile.updated_at.isoformat() if profile.updated_at else None,
    )


# ──────────────────────────────────────────────────────────
# CRUD 端点
# ──────────────────────────────────────────────────────────

@router.get("", response_model=list[ScanProfileResponse] | list[ScanProfileBrief])
async def list_profiles(
    brief: bool = Query(False, description="简要模式，用于下拉选择"),
    db: AsyncSession = Depends(get_db),
):
    """获取所有扫描策略列表"""
    result = await db.execute(
        select(ScanProfile).order_by(ScanProfile.is_default.desc(), ScanProfile.id)
    )
    profiles = result.scalars().all()

    if brief:
        return [ScanProfileBrief.model_validate(p) for p in profiles]
    return [_profile_to_response(p) for p in profiles]


@router.post("", response_model=ScanProfileResponse, status_code=201)
async def create_profile(
    data: ScanProfileCreate,
    db: AsyncSession = Depends(get_db),
):
    """创建扫描策略"""
    # 名称唯一性检查
    existing = await db.execute(
        select(ScanProfile).where(ScanProfile.name == data.name)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"策略名称 '{data.name}' 已存在")

    profile = ScanProfile(
        name=data.name,
        description=data.description,
        port_scan=data.port_scan.model_dump(),
        service_detect=data.service_detect.model_dump(),
        script_scan=data.script_scan.model_dump(),
        os_detect=data.os_detect.model_dump(),
        timing=data.timing.model_dump(),
    )
    db.add(profile)
    await db.commit()
    await db.refresh(profile)
    return _profile_to_response(profile)


@router.get("/{profile_id}", response_model=ScanProfileResponse)
async def get_profile(
    profile_id: int,
    db: AsyncSession = Depends(get_db),
):
    """获取扫描策略详情"""
    profile = await _get_profile_or_404(db, profile_id)
    return _profile_to_response(profile)


@router.put("/{profile_id}", response_model=ScanProfileResponse)
async def update_profile(
    profile_id: int,
    data: ScanProfileUpdate,
    db: AsyncSession = Depends(get_db),
):
    """更新扫描策略"""
    profile = await _get_profile_or_404(db, profile_id)

    # 名称唯一性检查（如果改了名）
    if data.name is not None and data.name != profile.name:
        existing = await db.execute(
            select(ScanProfile).where(ScanProfile.name == data.name)
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail=f"策略名称 '{data.name}' 已存在")

    # 逐字段更新
    update_data = data.model_dump(exclude_unset=True)
    for field_name, value in update_data.items():
        if field_name in ("port_scan", "service_detect", "script_scan",
                          "os_detect", "timing"):
            # Pydantic子模型 → dict
            setattr(profile, field_name, value.model_dump()
                    if hasattr(value, "model_dump") else value)
        else:
            setattr(profile, field_name, value)

    await db.commit()
    await db.refresh(profile)
    return _profile_to_response(profile)


@router.delete("/{profile_id}")
async def delete_profile(
    profile_id: int,
    db: AsyncSession = Depends(get_db),
):
    """删除扫描策略（内置策略不可删除）"""
    profile = await _get_profile_or_404(db, profile_id)

    if profile.is_builtin:
        raise HTTPException(status_code=403, detail="内置策略不可删除")

    # 检查是否有关联的扫描任务
    task_count = await db.execute(
        select(ScanTask).where(ScanTask.scan_profile_id == profile_id).limit(1)
    )
    if task_count.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail=f"策略 #{profile_id} 仍有关联的扫描任务，无法删除"
        )

    await db.delete(profile)
    await db.commit()
    return {"message": f"策略 '{profile.name}' 已删除"}


@router.put("/{profile_id}/default", response_model=ScanProfileResponse)
async def set_default_profile(
    profile_id: int,
    db: AsyncSession = Depends(get_db),
):
    """将指定策略设为默认（同时取消其他默认）"""
    profile = await _get_profile_or_404(db, profile_id)

    # 取消现有默认
    current_defaults = await db.execute(
        select(ScanProfile).where(ScanProfile.is_default == True)
    )
    for p in current_defaults.scalars().all():
        p.is_default = False

    # 设置新默认
    profile.is_default = True
    await db.commit()
    await db.refresh(profile)
    return _profile_to_response(profile)
