
from contextlib import asynccontextmanager
import os
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from app.config import settings
from app.database import init_db, async_session
from app.models.models import User, UserRole
from app.services.auth import get_password_hash
from app.api import auth, users, discovery, host_discovery, service_discovery, assets, vulns, sysconfig
from sqlalchemy import select

logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    async with async_session() as db:
        result = await db.execute(select(User).where(User.username == "admin"))
        if not result.scalar_one_or_none():
            admin_password = os.getenv("ADMIN_DEFAULT_PASSWORD", "")
            if not admin_password:
                logger.warning("ADMIN_DEFAULT_PASSWORD not set, skipping default admin creation.")
            elif len(admin_password) < 15:
                logger.error("ADMIN_DEFAULT_PASSWORD must be at least 15 characters. Refusing to create admin with weak password.")
            else:
                admin = User(username="admin", email="admin@netguard.local", hashed_password=get_password_hash(admin_password), role=UserRole.admin, is_active=True)
                db.add(admin)
                await db.commit()
                logger.info("Default admin user created. Please change the password after first login.")
    try:
        from app.services.scheduler import scheduler_service
        await scheduler_service.start()
    except Exception as e:
        logger.error(f"Failed to start scheduler: {e}")
    try:
        from app.services.vuln_service import vuln_scheduler
        await vuln_scheduler.start()
    except Exception as e:
        logger.error(f"Failed to start vuln scheduler: {e}")
    yield
    try:
        from app.services.scheduler import scheduler_service
        await scheduler_service.stop()
    except Exception as e:
        logger.error(f"Failed to stop scheduler: {e}")
    try:
        from app.services.vuln_service import vuln_scheduler
        await vuln_scheduler.stop()
    except Exception as e:
        logger.error(f"Failed to stop vuln scheduler: {e}")

app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(auth.router, prefix="/api")
app.include_router(users.router, prefix="/api")
app.include_router(discovery.router, prefix="/api")
app.include_router(host_discovery.router)
app.include_router(service_discovery.router)
app.include_router(assets.router, prefix="/api")
app.include_router(vulns.router, prefix="/api")
app.include_router(sysconfig.router, prefix="/api")

@app.get("/api/health")
async def health():
    return {"status": "ok", "version": settings.APP_VERSION}

frontend_dist = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "dist")
if os.path.isdir(frontend_dist):
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")
