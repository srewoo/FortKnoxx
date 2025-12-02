"""
Scan Worker for FortKnoxx Job Queue
Processes jobs from the queue asynchronously
"""

import asyncio
import logging
from typing import Optional, Callable, Dict, Any
from .queue import JobQueue, Job, JobStatus, job_queue
import uuid

logger = logging.getLogger(__name__)


class ScanWorker:
    """Async worker that processes scan jobs"""

    def __init__(
        self,
        queue: Optional[JobQueue] = None,
        worker_id: Optional[str] = None
    ):
        """
        Initialize scan worker

        Args:
            queue: Job queue to process
            worker_id: Unique worker ID
        """
        self.queue = queue or job_queue
        self.worker_id = worker_id or str(uuid.uuid4())
        self.is_running = False
        self.current_job: Optional[Job] = None

        # Job handlers registry
        self.handlers: Dict[str, Callable] = {}

    def register_handler(self, job_type: str, handler: Callable):
        """
        Register a handler function for a job type

        Args:
            job_type: Type of job (e.g., "security_scan")
            handler: Async function to handle the job
        """
        self.handlers[job_type] = handler
        logger.info(f"Handler registered for job type: {job_type}")

    async def process_job(self, job: Job) -> bool:
        """
        Process a single job

        Args:
            job: Job to process

        Returns:
            True if successful, False otherwise
        """
        try:
            self.current_job = job
            job.worker_id = self.worker_id

            # Update status to running
            await self.queue.update_job_status(job.id, JobStatus.RUNNING)

            logger.info(
                f"Worker {self.worker_id} processing job {job.id} "
                f"(type: {job.type})"
            )

            # Get handler for job type
            handler = self.handlers.get(job.type)
            if not handler:
                raise Exception(f"No handler registered for job type: {job.type}")

            # Execute handler with timeout
            try:
                result = await asyncio.wait_for(
                    handler(job),
                    timeout=job.timeout_seconds
                )

                # Mark as completed
                await self.queue.update_job_status(
                    job.id,
                    JobStatus.COMPLETED,
                    result=result
                )

                logger.info(
                    f"Job {job.id} completed successfully "
                    f"(elapsed: {job.elapsed_seconds()}s)"
                )
                return True

            except asyncio.TimeoutError:
                logger.error(f"Job {job.id} timed out after {job.timeout_seconds}s")
                await self.queue.update_job_status(
                    job.id,
                    JobStatus.TIMEOUT,
                    error="Job execution timed out"
                )
                return False

        except Exception as e:
            error_msg = f"Job execution error: {str(e)}"
            logger.error(f"Job {job.id} failed: {error_msg}")

            await self.queue.update_job_status(
                job.id,
                JobStatus.FAILED,
                error=error_msg
            )

            # Retry if allowed
            if job.retry_count < job.max_retries:
                await self.queue.retry_job(job.id)

            return False

        finally:
            self.current_job = None

    async def run(self, poll_interval: float = 1.0):
        """
        Start worker loop to process jobs from queue

        Args:
            poll_interval: Seconds to wait between queue polls
        """
        self.is_running = True
        logger.info(f"Worker {self.worker_id} started")

        try:
            while self.is_running:
                # Get next job from queue
                job = await self.queue.dequeue()

                if job:
                    await self.process_job(job)
                else:
                    # No jobs available, wait before polling again
                    await asyncio.sleep(poll_interval)

        except Exception as e:
            logger.error(f"Worker {self.worker_id} error: {str(e)}")
        finally:
            logger.info(f"Worker {self.worker_id} stopped")

    def stop(self):
        """Stop the worker"""
        self.is_running = False
        logger.info(f"Worker {self.worker_id} stopping...")

    async def health_check(self) -> Dict[str, Any]:
        """Get worker health status"""
        return {
            "worker_id": self.worker_id,
            "is_running": self.is_running,
            "current_job": self.current_job.id if self.current_job else None,
            "registered_handlers": list(self.handlers.keys())
        }
