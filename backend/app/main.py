
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from app.config import settings
from app.database import init_db, async_session
from app.models.models import User, UserRole
from app.services.auth import get_password_hash
from app.api import auth, users, discovery, assets, vulns, settings
from sqlalchemy import select
import os

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    async with async_session() as db:
        result = await db.execute(select(User).where(User.username == "admin"))
        if not result.scalar_one_or_none():
            admin = User(username="admin", email="admin@netguard.local", hashed_password=get_password_hash("netguard123"), role=UserRole.admin, is_active=True)
            db.add(admin)
            await db.commit()
    yield

app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api")
app.include_router(users.router, prefix="/api")
app.include_router(discovery.router, prefix="/api")
app.include_router(assets.router, prefix="/api")
app.include_router(vulns.router, prefix="/api")

@app.get("/api/health")
async def health():
    return {"status": "ok", "version": settings.APP_VERSION}

frontend_dist = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "dist")
if os.path.isdir(frontend_dist):
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")
