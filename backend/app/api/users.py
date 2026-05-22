
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db
from app.models.models import User, UserRole
from app.middleware.auth import require_role

router = APIRouter(prefix="/users", tags=["用户管理"])

@router.get("/")
async def list_users(db: AsyncSession = Depends(get_db), current_user: User = Depends(require_role(UserRole.admin))):
    result = await db.execute(select(User))
    users = result.scalars().all()
    return {"items": [{"id": u.id, "username": u.username, "email": u.email, "role": u.role, "is_active": u.is_active, "created_at": str(u.created_at)} for u in users]}

@router.put("/{user_id}")
async def update_user(user_id: int, data: dict, db: AsyncSession = Depends(get_db), current_user: User = Depends(require_role(UserRole.admin))):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    if "role" in data:
        user.role = UserRole(data["role"])
    if "is_active" in data:
        user.is_active = data["is_active"]
    await db.commit()
    return {"message": "用户已更新"}

@router.delete("/{user_id}")
async def delete_user(user_id: int, db: AsyncSession = Depends(get_db), current_user: User = Depends(require_role(UserRole.admin))):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="不能删除自己")
    await db.delete(user)
    await db.commit()
    return {"message": "用户已删除"}
