"""
Job Queue Manager for FortKnoxx
Manages async scan jobs with Redis or in-memory fallback
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, Dict, Any, List, Callable
from datetime import datetime, timezone, timedelta
from enum import Enum
import uuid
import asyncio
import logging
from collections import deque

logger = logging.getLogger(__name__)


class JobStatus(str, Enum):
    """Job execution status"""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class JobPriority(str, Enum):
    """Job priority levels"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class Job(BaseModel):
    """Job model"""
    model_config = ConfigDict(extra="ignore")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: str  # e.g., "security_scan", "logic_scan", "llm_security_scan"
    status: JobStatus = JobStatus.QUEUED
    priority: JobPriority = JobPriority.NORMAL

    # Job parameters
    repo_id: str
    scan_id: str
    parameters: Dict[str, Any] = Field(default_factory=dict)

    # Execution tracking
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    timeout_seconds: int = 3600  # 1 hour default

    # Results and errors
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    # Retry configuration
    retry_count: int = 0
    max_retries: int = 3

    # Worker assignment
    worker_id: Optional[str] = None

    def elapsed_seconds(self) -> int:
        """Calculate elapsed time"""
        if self.started_at:
            end_time = self.completed_at or datetime.now(timezone.utc)
            return int((end_time - self.started_at).total_seconds())
        return 0

    def is_timed_out(self) -> bool:
        """Check if job has timed out"""
        if self.status == JobStatus.RUNNING and self.started_at:
            elapsed = self.elapsed_seconds()
            return elapsed > self.timeout_seconds
        return False


class JobQueue:
    """
    Distributed job queue manager
    Supports Redis backend or in-memory fallback
    """

    def __init__(self, use_redis: bool = False, redis_url: Optional[str] = None):
        """
        Initialize job queue

        Args:
            use_redis: Whether to use Redis backend
            redis_url: Redis connection URL
        """
        self.use_redis = use_redis
        self.redis_url = redis_url

        # In-memory storage (fallback or dev mode)
        self.jobs: Dict[str, Job] = {}
        self.queue: deque = deque()  # FIFO queue
        self.priority_queue: deque = deque()  # High priority queue

        # Redis client (if enabled)
        self.redis_client = None
        if use_redis:
            try:
                import redis
                self.redis_client = redis.from_url(redis_url or "redis://localhost:6379")
                logger.info("Redis job queue initialized")
            except Exception as e:
                logger.warning(f"Redis not available, using in-memory queue: {str(e)}")
                self.use_redis = False

    async def enqueue(
        self,
        job_type: str,
        repo_id: str,
        scan_id: str,
        parameters: Optional[Dict[str, Any]] = None,
        priority: JobPriority = JobPriority.NORMAL,
        timeout_seconds: int = 3600
    ) -> Job:
        """
        Add a job to the queue

        Args:
            job_type: Type of job (e.g., "security_scan")
            repo_id: Repository ID
            scan_id: Scan ID
            parameters: Job parameters
            priority: Job priority
            timeout_seconds: Timeout in seconds

        Returns:
            Created Job object
        """
        job = Job(
            type=job_type,
            repo_id=repo_id,
            scan_id=scan_id,
            parameters=parameters or {},
            priority=priority,
            timeout_seconds=timeout_seconds
        )

        # Store job
        self.jobs[job.id] = job

        # Add to appropriate queue
        if priority in [JobPriority.HIGH, JobPriority.URGENT]:
            self.priority_queue.append(job.id)
        else:
            self.queue.append(job.id)

        logger.info(
            f"Job enqueued: {job.id} (type: {job_type}, priority: {priority})"
        )

        return job

    async def dequeue(self) -> Optional[Job]:
        """
        Get next job from queue (priority first)

        Returns:
            Next Job or None if queue is empty
        """
        job_id = None

        # Check priority queue first
        if self.priority_queue:
            job_id = self.priority_queue.popleft()
        elif self.queue:
            job_id = self.queue.popleft()

        if job_id and job_id in self.jobs:
            return self.jobs[job_id]

        return None

    async def get_job(self, job_id: str) -> Optional[Job]:
        """Get job by ID"""
        return self.jobs.get(job_id)

    async def update_job_status(
        self,
        job_id: str,
        status: JobStatus,
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None
    ) -> bool:
        """
        Update job status

        Args:
            job_id: Job ID
            status: New status
            result: Optional result data
            error: Optional error message

        Returns:
            True if updated successfully
        """
        job = self.jobs.get(job_id)
        if not job:
            return False

        job.status = status

        if status == JobStatus.RUNNING:
            job.started_at = datetime.now(timezone.utc)
        elif status in [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED]:
            job.completed_at = datetime.now(timezone.utc)

        if result:
            job.result = result

        if error:
            job.error = error

        logger.info(f"Job {job_id} status updated to {status}")
        return True

    async def cancel_job(self, job_id: str) -> bool:
        """Cancel a job"""
        return await self.update_job_status(job_id, JobStatus.CANCELLED)

    async def retry_job(self, job_id: str) -> bool:
        """
        Retry a failed job

        Args:
            job_id: Job ID

        Returns:
            True if re-queued successfully
        """
        job = self.jobs.get(job_id)
        if not job or job.retry_count >= job.max_retries:
            return False

        job.retry_count += 1
        job.status = JobStatus.QUEUED
        job.started_at = None
        job.completed_at = None
        job.error = None

        # Re-add to queue
        if job.priority in [JobPriority.HIGH, JobPriority.URGENT]:
            self.priority_queue.append(job.id)
        else:
            self.queue.append(job.id)

        logger.info(f"Job {job_id} re-queued (retry {job.retry_count}/{job.max_retries})")
        return True

    async def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics"""
        total_jobs = len(self.jobs)
        queued = sum(1 for j in self.jobs.values() if j.status == JobStatus.QUEUED)
        running = sum(1 for j in self.jobs.values() if j.status == JobStatus.RUNNING)
        completed = sum(1 for j in self.jobs.values() if j.status == JobStatus.COMPLETED)
        failed = sum(1 for j in self.jobs.values() if j.status == JobStatus.FAILED)

        return {
            "total_jobs": total_jobs,
            "queued": queued,
            "running": running,
            "completed": completed,
            "failed": failed,
            "queue_length": len(self.queue),
            "priority_queue_length": len(self.priority_queue),
            "backend": "redis" if self.use_redis else "in-memory"
        }

    async def cleanup_old_jobs(self, days: int = 7):
        """Remove jobs older than specified days"""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        removed = 0

        for job_id in list(self.jobs.keys()):
            job = self.jobs[job_id]
            if job.created_at < cutoff and job.status in [
                JobStatus.COMPLETED,
                JobStatus.FAILED,
                JobStatus.CANCELLED
            ]:
                del self.jobs[job_id]
                removed += 1

        logger.info(f"Cleaned up {removed} old jobs")
        return removed


# Global job queue instance
job_queue = JobQueue()
