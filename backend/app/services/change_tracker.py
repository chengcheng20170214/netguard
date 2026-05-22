
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.models import Asset, AssetSnapshot, AssetChange, ChangeType, ChangeSeverity
from datetime import datetime, timezone

async def create_snapshot(db: AsyncSession, asset: Asset, scan_task_id: int | None = None) -> AssetSnapshot:
    snapshot = AssetSnapshot(
        asset_id=asset.id,
        scan_task_id=scan_task_id,
        ip=asset.ip,
        mac=asset.mac,
        hostname=asset.hostname,
        os=asset.os,
        ports=asset.current_ports or [],
        created_at=datetime.now(timezone.utc)
    )
    db.add(snapshot)
    await db.commit()
    await db.refresh(snapshot)
    return snapshot

def _ports_to_dict(ports: list) -> dict:
    return {f"{p.get('port')}/{p.get('proto','tcp')}" : p for p in (ports or [])}

async def compare_snapshots(db: AsyncSession, before: AssetSnapshot, after: AssetSnapshot) -> list[AssetChange]:
    changes = []

    if before.os != after.os and after.os:
        changes.append(AssetChange(
            asset_id=after.asset_id, ip=after.ip, change_type=ChangeType.os_changed,
            detail={"field": "os", "old": before.os, "new": after.os},
            snapshot_before_id=before.id, snapshot_after_id=after.id,
            severity=ChangeSeverity.info, detected_at=datetime.now(timezone.utc)
        ))

    if before.hostname != after.hostname and after.hostname:
        changes.append(AssetChange(
            asset_id=after.asset_id, ip=after.ip, change_type=ChangeType.hostname_changed,
            detail={"field": "hostname", "old": before.hostname, "new": after.hostname},
            snapshot_before_id=before.id, snapshot_after_id=after.id,
            severity=ChangeSeverity.info, detected_at=datetime.now(timezone.utc)
        ))

    before_ports = _ports_to_dict(before.ports)
    after_ports = _ports_to_dict(after.ports)

    for key, port_info in after_ports.items():
        if key not in before_ports:
            changes.append(AssetChange(
                asset_id=after.asset_id, ip=after.ip, change_type=ChangeType.new_service,
                detail={"port": port_info.get("port"), "proto": port_info.get("proto"), "service": port_info.get("service")},
                snapshot_before_id=before.id, snapshot_after_id=after.id,
                severity=ChangeSeverity.info, detected_at=datetime.now(timezone.utc)
            ))
        else:
            old_ver = before_ports[key].get("version", "")
            new_ver = port_info.get("version", "")
            if old_ver and new_ver and old_ver != new_ver:
                changes.append(AssetChange(
                    asset_id=after.asset_id, ip=after.ip, change_type=ChangeType.version_changed,
                    detail={"port": port_info.get("port"), "service": port_info.get("service"), "old_version": old_ver, "new_version": new_ver},
                    snapshot_before_id=before.id, snapshot_after_id=after.id,
                    severity=ChangeSeverity.warning, detected_at=datetime.now(timezone.utc)
                ))

    for key, port_info in before_ports.items():
        if key not in after_ports:
            changes.append(AssetChange(
                asset_id=after.asset_id, ip=after.ip, change_type=ChangeType.service_closed,
                detail={"port": port_info.get("port"), "proto": port_info.get("proto"), "service": port_info.get("service")},
                snapshot_before_id=before.id, snapshot_after_id=after.id,
                severity=ChangeSeverity.warning, detected_at=datetime.now(timezone.utc)
            ))

    for change in changes:
        db.add(change)
    if changes:
        await db.commit()

    return changes
