from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import select
from app.config import settings

engine = create_async_engine(settings.DATABASE_URL, echo=settings.DEBUG)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # 初始化内置 ScanProfile 预设（对应设计文档附录C）
    await _init_builtin_profiles()


async def _init_builtin_profiles():
    """首次启动时插入内置扫描策略预设，已存在则跳过"""
    from app.models.models import ScanProfile

    # 内置预设定义（对应设计文档附录C 4组配置）
    BUILTIN_PROFILES = [
        {
            "name": "快速探测",
            "description": "Top1000端口快速扫描，无服务识别和脚本，适合快速摸底",
            "is_default": True,
            "is_builtin": True,
            "port_scan": {
                "mode": "top1000",
                "top_ports": 1000,
                "scan_mode": "standard",
                "max_concurrent": 4,
            },
            "service_detect": {"enabled": False, "intensity": 7, "all_ports": False},
            "script_scan": {"enabled": False, "categories": ["default", "safe"],
                            "custom_scripts": "", "script_args": ""},
            "os_detect": {"enabled": False, "max_tries": 2, "scan_guess": False},
            "timing": {
                "host_timeout": 0,
                "nmap_timeout_sec": 3600,
                "script_timeout_sec": 60,
                "max_retries": 3,
                "min_rate": 300,
                "max_rtt_timeout_ms": 500,
                "initial_rtt_timeout_ms": 200,
                "max_scan_delay_ms": 10,
                "phase_executor": "grouped",
            },
        },
        {
            "name": "标准扫描",
            "description": "Top1000端口 + 服务版本识别，适合日常巡检",
            "is_default": False,
            "is_builtin": True,
            "port_scan": {
                "mode": "top1000",
                "top_ports": 1000,
                "scan_mode": "standard",
                "max_concurrent": 4,
            },
            "service_detect": {"enabled": True, "intensity": 7, "all_ports": False},
            "script_scan": {"enabled": False, "categories": ["default", "safe"],
                            "custom_scripts": "", "script_args": ""},
            "os_detect": {"enabled": False, "max_tries": 2, "scan_guess": False},
            "timing": {
                "host_timeout": 300,
                "nmap_timeout_sec": 7200,
                "script_timeout_sec": 60,
                "max_retries": 3,
                "min_rate": 300,
                "max_rtt_timeout_ms": 500,
                "initial_rtt_timeout_ms": 200,
                "max_scan_delay_ms": 10,
                "phase_executor": "grouped",
            },
        },
        {
            "name": "深度扫描",
            "description": "Top1000端口 + 服务识别 + default/safe脚本，适合安全评估",
            "is_default": False,
            "is_builtin": True,
            "port_scan": {
                "mode": "top1000",
                "top_ports": 1000,
                "scan_mode": "ip_sequential",
                "max_concurrent": 4,
            },
            "service_detect": {"enabled": True, "intensity": 7, "all_ports": False},
            "script_scan": {"enabled": True, "categories": ["default", "safe", "vuln"],
                            "custom_scripts": "", "script_args": ""},
            "os_detect": {"enabled": False, "max_tries": 2, "scan_guess": False},
            "timing": {
                "host_timeout": 600,
                "nmap_timeout_sec": 21600,
                "script_timeout_sec": 120,
                "max_retries": 2,
                "min_rate": 100,
                "max_rtt_timeout_ms": 1000,
                "initial_rtt_timeout_ms": 500,
                "max_scan_delay_ms": 20,
                "phase_executor": "serial",
            },
        },
        {
            "name": "全端口扫描",
            "description": "65535全端口 + 服务识别 + 脚本，耗时长但最全面，适合关键资产审计",
            "is_default": False,
            "is_builtin": True,
            "port_scan": {
                "mode": "full",
                "top_ports": 1000,
                "scan_mode": "ip_sequential",
                "max_concurrent": 2,
            },
            "service_detect": {"enabled": True, "intensity": 9, "all_ports": True},
            "script_scan": {"enabled": True, "categories": ["default", "safe", "vuln"],
                            "custom_scripts": "", "script_args": ""},
            "os_detect": {"enabled": True, "max_tries": 2, "scan_guess": False},
            "timing": {
                "host_timeout": 1200,
                "nmap_timeout_sec": 86400,
                "script_timeout_sec": 180,
                "max_retries": 1,
                "min_rate": 50,
                "max_rtt_timeout_ms": 2000,
                "initial_rtt_timeout_ms": 1000,
                "max_scan_delay_ms": 50,
                "phase_executor": "serial",
            },
        },
    ]

    async with async_session() as session:
        for preset in BUILTIN_PROFILES:
            # 按名称检查是否已存在
            result = await session.execute(
                select(ScanProfile).where(ScanProfile.name == preset["name"])
            )
            existing = result.scalar_one_or_none()
            if not existing:
                profile = ScanProfile(**preset)
                session.add(profile)

        await session.commit()
