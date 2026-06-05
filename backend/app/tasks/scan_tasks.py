
import asyncio
import logging
from .celery_app import celery_app
from app.services.scan_executor import execute_scan

logger = logging.getLogger(__name__)


@celery_app.task(bind=True)
def run_scan_task(self, scan_task_id: int, targets: str, scan_mode: str, ports: str | None = None):
    """Celery 任务入口
    
    新版 execute_scan 不再接受 progress_callback / celery_task_id 参数。
    进度更新由 scan_executor 内部直接操作 DB 实现。
    """
    logger.info(f"Celery task started: scan_task_id={scan_task_id}")
    asyncio.run(execute_scan(scan_task_id))
