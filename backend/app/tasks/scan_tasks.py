
import asyncio
import logging
from datetime import datetime, timezone
from .celery_app import celery_app
from app.services.scan_executor import execute_scan

logger = logging.getLogger(__name__)


@celery_app.task(bind=True)
def run_scan_task(self, scan_task_id: int, targets: str, scan_mode: str, scan_methods: list, ports: str | None = None):
    def progress_callback(progress):
        self.update_state(state="PROGRESS", meta={"progress": progress})

    asyncio.run(execute_scan(scan_task_id, progress_callback=progress_callback, celery_task_id=self.request.id))
