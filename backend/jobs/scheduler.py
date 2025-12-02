"""
Scan Scheduler for FortKnoxx
Manages multiple workers and job scheduling
"""

import asyncio
import logging
from typing import List, Dict, Any, Callable, Optional
from .worker import ScanWorker
from .queue import JobQueue, job_queue

logger = logging.getLogger(__name__)


class ScanScheduler:
    """Manages multiple workers and coordinates job execution"""

    def __init__(
        self,
        queue: Optional[JobQueue] = None,
        num_workers: int = 4
    ):
        """
        Initialize scan scheduler

        Args:
            queue: Job queue to use
            num_workers: Number of worker processes to spawn
        """
        self.queue = queue or job_queue
        self.num_workers = num_workers
        self.workers: List[ScanWorker] = []
        self.worker_tasks: List[asyncio.Task] = []
        self.is_running = False

        # Shared handlers for all workers
        self.handlers: Dict[str, Callable] = {}

    def register_handler(self, job_type: str, handler: Callable):
        """
        Register a job handler that will be shared across all workers

        Args:
            job_type: Type of job
            handler: Handler function
        """
        self.handlers[job_type] = handler
        logger.info(f"Handler registered: {job_type}")

        # Update existing workers
        for worker in self.workers:
            worker.register_handler(job_type, handler)

    async def start(self):
        """Start the scheduler and spawn workers"""
        if self.is_running:
            logger.warning("Scheduler already running")
            return

        self.is_running = True
        logger.info(f"Starting scheduler with {self.num_workers} workers")

        # Create and start workers
        for i in range(self.num_workers):
            worker = ScanWorker(queue=self.queue)

            # Register all handlers
            for job_type, handler in self.handlers.items():
                worker.register_handler(job_type, handler)

            self.workers.append(worker)

            # Start worker in background
            task = asyncio.create_task(worker.run())
            self.worker_tasks.append(task)

        logger.info(f"Scheduler started with {len(self.workers)} workers")

    async def stop(self):
        """Stop the scheduler and all workers"""
        if not self.is_running:
            return

        self.is_running = False
        logger.info("Stopping scheduler...")

        # Stop all workers
        for worker in self.workers:
            worker.stop()

        # Wait for all worker tasks to complete
        if self.worker_tasks:
            await asyncio.gather(*self.worker_tasks, return_exceptions=True)

        self.workers.clear()
        self.worker_tasks.clear()

        logger.info("Scheduler stopped")

    async def get_status(self) -> Dict[str, Any]:
        """Get scheduler status"""
        worker_statuses = []
        for worker in self.workers:
            status = await worker.health_check()
            worker_statuses.append(status)

        queue_stats = await self.queue.get_queue_stats()

        return {
            "is_running": self.is_running,
            "num_workers": len(self.workers),
            "workers": worker_statuses,
            "queue": queue_stats,
            "registered_handlers": list(self.handlers.keys())
        }

    async def scale_workers(self, new_count: int):
        """
        Scale the number of workers up or down

        Args:
            new_count: New number of workers
        """
        current_count = len(self.workers)

        if new_count == current_count:
            return

        if new_count > current_count:
            # Scale up - add more workers
            for i in range(new_count - current_count):
                worker = ScanWorker(queue=self.queue)

                # Register all handlers
                for job_type, handler in self.handlers.items():
                    worker.register_handler(job_type, handler)

                self.workers.append(worker)

                # Start worker
                task = asyncio.create_task(worker.run())
                self.worker_tasks.append(task)

            logger.info(f"Scaled up to {new_count} workers")

        else:
            # Scale down - remove workers
            workers_to_remove = current_count - new_count

            for i in range(workers_to_remove):
                worker = self.workers.pop()
                worker.stop()

                if self.worker_tasks:
                    task = self.worker_tasks.pop()
                    # Don't wait for task, it will finish when worker stops

            logger.info(f"Scaled down to {new_count} workers")


# Global scheduler instance
scheduler = ScanScheduler()
