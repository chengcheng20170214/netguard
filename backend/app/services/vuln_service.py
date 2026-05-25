
import asyncio
import logging
from datetime import datetime, timezone, timedelta
from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import async_session
from app.models.models import Asset, Vulnerability, VulnDB, SystemConfig
from app.services.nvd import search_cve_local, download_nvd_feed_full, download_nvd_feed_modified, set_progress_callback

logger = logging.getLogger(__name__)

VULN_SCAN_INTERVAL_KEY = "vuln_auto_scan_interval"
VULN_LAST_SCAN_KEY = "vuln_last_scan_time"
VULN_AUTO_ENABLED_KEY = "vuln_auto_scan_enabled"
VULN_LAST_FULL_UPDATE_KEY = "vuln_last_full_update"
VULN_LAST_INCREMENTAL_KEY = "vuln_last_incremental_update"

_update_progress = {"percent": 0, "message": ""}


async def _get_config_value(key: str) -> str | None:
    async with async_session() as db:
        result = await db.execute(select(SystemConfig).where(SystemConfig.key == key))
        entry = result.scalar_one_or_none()
        return entry.value if entry else None


async def _set_config_value(key: str, value: str):
    async with async_session() as db:
        result = await db.execute(select(SystemConfig).where(SystemConfig.key == key))
        entry = result.scalar_one_or_none()
        if entry:
            entry.value = value
            entry.updated_at = datetime.now(timezone.utc)
        else:
            entry = SystemConfig(key=key, value=value, description=key, is_secret=False)
            db.add(entry)
        await db.commit()


async def scan_asset_vulns(asset_id: int) -> list[str]:
    async with async_session() as db:
        result = await db.execute(select(Asset).where(Asset.id == asset_id))
        asset = result.scalar_one_or_none()
        if not asset:
            return []

        found = []
        for port_info in (asset.current_ports or []):
            service = port_info.get("service", "")
            version = port_info.get("version", "")
            if not service:
                continue

            cves = await search_cve_local(service, version or None)
            for cve in cves:
                existing = await db.execute(
                    select(Vulnerability).where(
                        Vulnerability.asset_id == asset.id,
                        Vulnerability.cve_id == cve["cve_id"]
                    )
                )
                if existing.scalar_one_or_none():
                    continue
                vuln = Vulnerability(
                    asset_id=asset.id, cve_id=cve["cve_id"],
                    cve_description=cve.get("cve_description"),
                    cvss_score=cve.get("cvss_score"), severity=cve.get("severity"),
                    affected_service=service, affected_version=version,
                    remediation=cve.get("remediation"),
                    created_at=datetime.now(timezone.utc)
                )
                db.add(vuln)
                found.append(cve["cve_id"])

        await db.commit()
    return found


async def scan_all_assets() -> dict:
    async with async_session() as db:
        result = await db.execute(select(Asset).where(Asset.is_online == True))
        assets = result.scalars().all()

    total_found = []
    errors = []
    for asset in assets:
        try:
            found = await scan_asset_vulns(asset.id)
            total_found.extend(found)
        except Exception as e:
            errors.append(f"资产 {asset.ip}: {str(e)}")

    await _record_scan_time()
    return {"scanned_assets": len(assets), "found_cves": len(total_found), "cves": total_found, "errors": errors}


async def update_vuln_db_full() -> dict:
    global _update_progress
    _update_progress = {"percent": 0, "message": "开始全量下载..."}

    def on_progress(pct, msg):
        global _update_progress
        _update_progress = {"percent": int(pct), "message": msg}

    set_progress_callback(on_progress)
    result = await download_nvd_feed_full()
    set_progress_callback(None)

    await _set_config_value(VULN_LAST_FULL_UPDATE_KEY, datetime.now(timezone.utc).isoformat())
    await _record_scan_time()
    _update_progress = {"percent": 100, "message": "全量更新完成"}
    return result


async def update_vuln_db_incremental() -> dict:
    global _update_progress
    _update_progress = {"percent": 0, "message": "开始增量更新..."}

    def on_progress(pct, msg):
        global _update_progress
        _update_progress = {"percent": int(pct), "message": msg}

    set_progress_callback(on_progress)
    result = await download_nvd_feed_modified()
    set_progress_callback(None)

    await _set_config_value(VULN_LAST_INCREMENTAL_KEY, datetime.now(timezone.utc).isoformat())
    await _record_scan_time()
    _update_progress = {"percent": 100, "message": "增量更新完成"}
    return result


def get_update_progress() -> dict:
    return _update_progress


async def get_vuln_db_status() -> dict:
    async with async_session() as db:
        from sqlalchemy import func
        count_result = await db.execute(select(func.count()).select_from(VulnDB))
        total = count_result.scalar()

        latest_result = await db.execute(
            select(VulnDB.fetched_at).order_by(VulnDB.fetched_at.desc()).limit(1)
        )
        latest = latest_result.scalar_one_or_none()

        sev_result = await db.execute(
            select(VulnDB.severity, func.count()).group_by(VulnDB.severity)
        )
        by_severity = {row[0] or "Unknown": row[1] for row in sev_result.all()}

    auto_enabled = (await _get_config_value(VULN_AUTO_ENABLED_KEY)) == "true"
    interval = int((await _get_config_value(VULN_SCAN_INTERVAL_KEY)) or "24")
    last_scan = await _get_config_value(VULN_LAST_SCAN_KEY)
    last_full = await _get_config_value(VULN_LAST_FULL_UPDATE_KEY)
    last_inc = await _get_config_value(VULN_LAST_INCREMENTAL_KEY)

    return {
        "total_cves": total,
        "last_updated": latest.isoformat() if latest else None,
        "by_severity": by_severity,
        "auto_scan_enabled": auto_enabled,
        "auto_scan_interval_hours": interval,
        "last_scan_time": last_scan,
        "last_full_update": last_full,
        "last_incremental_update": last_inc,
    }


async def _record_scan_time():
    await _set_config_value(VULN_LAST_SCAN_KEY, datetime.now(timezone.utc).isoformat())


class VulnScheduler:
    def __init__(self):
        self._task = None
        self._running = False

    async def start(self):
        enabled = (await _get_config_value(VULN_AUTO_ENABLED_KEY)) == "true"
        if enabled:
            self._running = True
            interval = int((await _get_config_value(VULN_SCAN_INTERVAL_KEY)) or "24")
            self._task = asyncio.create_task(self._loop(interval))
            logger.info(f"Vuln auto-scan started, interval={interval}h")

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
        logger.info("Vuln auto-scan stopped")

    async def restart(self, interval_hours: int):
        await self.stop()
        self._running = True
        self._task = asyncio.create_task(self._loop(interval_hours))
        logger.info(f"Vuln auto-scan restarted, interval={interval_hours}h")

    async def _loop(self, interval_hours: int):
        while self._running:
            try:
                logger.info("Running scheduled vuln scan + incremental update...")
                await update_vuln_db_incremental()
                result = await scan_all_assets()
                logger.info(f"Scheduled vuln scan done: {result}")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Scheduled vuln scan error: {e}")
            await asyncio.sleep(interval_hours * 3600)


vuln_scheduler = VulnScheduler()
