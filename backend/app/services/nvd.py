
import gzip
import json
import logging
import os
import tempfile
import asyncio
from datetime import datetime, timezone
import httpx
from app.config import settings

logger = logging.getLogger(__name__)

NVD_FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_client = httpx.AsyncClient(timeout=120.0, follow_redirects=True)

# Progress callback type: callable(progress_pct: float, message: str)
_progress_callback = None

def set_progress_callback(cb):
    global _progress_callback
    _progress_callback = cb

def _report_progress(pct: float, msg: str):
    if _progress_callback:
        _progress_callback(pct, msg)


async def download_nvd_feed_full() -> dict:
    """Download all yearly NVD JSON 2.0 feeds and return stats."""
    years = list(range(2002, datetime.now().year + 1))
    total_cves = 0
    total_cached = 0
    errors = []

    from app.database import async_session
    from app.models.models import VulnDB
    from sqlalchemy import select

    for i, year in enumerate(years):
        pct = (i / len(years)) * 100
        _report_progress(pct, f"下载 CVE-{year} 数据文件...")
        url = f"{NVD_FEED_BASE}/nvdcve-2.0-{year}.json.gz"
        try:
            resp = await _client.get(url)
            if resp.status_code != 200:
                errors.append(f"CVE-{year}: HTTP {resp.status_code}")
                continue

            decompressed = gzip.decompress(resp.content)
            data = json.loads(decompressed)
            cves = data.get("vulnerabilities", [])
            count = await _ingest_cves(cves)
            total_cves += len(cves)
            total_cached += count
            logger.info(f"NVD feed CVE-{year}: {len(cves)} records, {count} new cached")
        except Exception as e:
            errors.append(f"CVE-{year}: {str(e)[:100]}")
            logger.warning(f"Failed to download NVD feed for {year}: {e}")

        if not settings.NVD_API_KEY:
            await asyncio.sleep(0.5)

    _report_progress(100, f"完成，共处理 {total_cves} 条CVE")
    return {"total_cves": total_cves, "new_cached": total_cached, "errors": errors}


async def download_nvd_feed_modified() -> dict:
    """Download only the modified/recent NVD feed for incremental update."""
    total_cached = 0
    errors = []

    for feed_name in ["modified", "recent"]:
        _report_progress(0, f"下载增量更新 {feed_name}...")
        url = f"{NVD_FEED_BASE}/nvdcve-2.0-{feed_name}.json.gz"
        try:
            resp = await _client.get(url)
            if resp.status_code != 200:
                errors.append(f"{feed_name}: HTTP {resp.status_code}")
                continue

            decompressed = gzip.decompress(resp.content)
            data = json.loads(decompressed)
            cves = data.get("vulnerabilities", [])
            count = await _ingest_cves(cves)
            total_cached += count
            logger.info(f"NVD {feed_name} feed: {len(cves)} records, {count} updated")
        except Exception as e:
            errors.append(f"{feed_name}: {str(e)[:100]}")
            logger.warning(f"Failed to download NVD {feed_name} feed: {e}")

    _report_progress(100, f"增量更新完成，{total_cached} 条更新")
    return {"new_cached": total_cached, "errors": errors}


async def _ingest_cves(cves: list[dict]) -> int:
    """Parse NVD CVE list and upsert into VulnDB. Returns count of new/updated records."""
    from app.database import async_session
    from app.models.models import VulnDB
    from sqlalchemy import select

    count = 0
    batch_size = 200

    for batch_start in range(0, len(cves), batch_size):
        batch = cves[batch_start:batch_start + batch_size]
        async with async_session() as db:
            for vuln_item in batch:
                cve = vuln_item.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue

                parsed = _parse_cve_record(cve)

                existing = await db.execute(select(VulnDB).where(VulnDB.cve_id == cve_id))
                record = existing.scalar_one_or_none()
                if record:
                    record.cve_description = parsed["cve_description"]
                    record.cvss_score = parsed["cvss_score"]
                    record.cvss_version = parsed["cvss_version"]
                    record.severity = parsed["severity"]
                    record.remediation = parsed["remediation"]
                    record.published_date = parsed["published_date"]
                    record.last_modified = parsed["last_modified"]
                    record.fetched_at = datetime.now(timezone.utc)
                else:
                    db.add(VulnDB(
                        cve_id=cve_id,
                        cve_description=parsed["cve_description"],
                        cvss_score=parsed["cvss_score"],
                        cvss_version=parsed["cvss_version"],
                        severity=parsed["severity"],
                        remediation=parsed["remediation"],
                        published_date=parsed["published_date"],
                        last_modified=parsed["last_modified"],
                        fetched_at=datetime.now(timezone.utc),
                    ))
                count += 1
            await db.commit()

    return count


def _parse_iso_datetime(val: str | None) -> datetime | None:
    """Parse ISO 8601 datetime string to Python datetime object."""
    if not val:
        return None
    try:
        return datetime.fromisoformat(val.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _parse_cve_record(cve: dict) -> dict:
    """Parse a single NVD CVE 2.0 record into our schema fields."""
    cve_id = cve.get("id", "")

    descriptions = cve.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    cvss_score = None
    severity = None
    cvss_version = None
    metrics = cve.get("metrics", {})
    for ver_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if metrics.get(ver_key):
            cvss_data = metrics[ver_key][0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity") or metrics[ver_key][0].get("baseSeverity")
            cvss_version = cvss_data.get("version")
            break

    references = cve.get("references", [])
    remediation = None
    for ref in references:
        tags = ref.get("tags", [])
        if any(t.lower() in ("patch", "vendor advisory", "mitigation") for t in tags):
            remediation = ref.get("url")
            break

    published = _parse_iso_datetime(cve.get("published"))
    modified = _parse_iso_datetime(cve.get("lastModified"))

    return {
        "cve_id": cve_id,
        "cve_description": desc,
        "cvss_score": cvss_score,
        "cvss_version": cvss_version,
        "severity": severity,
        "remediation": remediation,
        "published_date": published,
        "last_modified": modified,
    }


async def search_cve(service_name: str, version: str | None = None) -> list[dict]:
    """Search CVE by keyword via NVD API (fallback for real-time queries)."""
    query = service_name
    if version:
        query += f" {version}"

    headers = {}
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY

    results = []
    try:
        resp = await _client.get(
            NVD_API_BASE,
            params={"keywordSearch": query, "resultsPerPage": 20},
            headers=headers
        )
        if resp.status_code == 200:
            data = resp.json()
            for vuln in data.get("vulnerabilities", []):
                parsed = _parse_cve_record(vuln.get("cve", {}))
                results.append(parsed)
        await asyncio.sleep(6 if not settings.NVD_API_KEY else 1)
    except Exception as e:
        logger.warning(f"NVD API search failed for '{query}': {e}")

    return results


async def search_cve_local(service_name: str, version: str | None = None) -> list[dict]:
    """Search CVE from local VulnDB cache first, fall back to API."""
    from app.database import async_session
    from app.models.models import VulnDB
    from sqlalchemy import select, or_

    async with async_session() as db:
        query_db = select(VulnDB).where(
            or_(
                VulnDB.cve_description.contains(service_name),
                VulnDB.cve_id.contains(service_name.upper()),
            )
        ).order_by(VulnDB.cvss_score.desc().nulls_last()).limit(20)
        result = await db.execute(query_db)
        local_results = result.scalars().all()

    if local_results:
        return [
            {
                "cve_id": r.cve_id,
                "cve_description": r.cve_description,
                "cvss_score": r.cvss_score,
                "severity": r.severity,
                "remediation": r.remediation,
            }
            for r in local_results
        ]

    return await search_cve(service_name, version)
