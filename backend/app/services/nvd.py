
import httpx
import asyncio
from app.config import settings

_nvd_client = httpx.AsyncClient(timeout=30.0)

async def search_cve(service_name: str, version: str | None = None) -> list[dict]:
    query = service_name
    if version:
        query += f" {version}"

    headers = {}
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY

    results = []
    try:
        resp = await _nvd_client.get(
            settings.NVD_API_URL,
            params={"keywordSearch": query, "resultsPerPage": 20},
            headers=headers
        )
        if resp.status_code == 200:
            data = resp.json()
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                descriptions = cve.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "")
                metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
                cvss_score = None
                severity = None
                if metrics:
                    cvss_data = metrics[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity")
                results.append({
                    "cve_id": cve_id,
                    "cve_description": desc,
                    "cvss_score": cvss_score,
                    "severity": severity,
                })
        await asyncio.sleep(6 if not settings.NVD_API_KEY else 1)
    except Exception:
        pass

    return results
