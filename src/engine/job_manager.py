# src/engine/job_manager.py
"""
JobManager: Simple in-memory job queue and status tracker for scan jobs.
"""

import threading
import uuid
from typing import Dict, Any
from engine.db import SessionLocal
from engine.models import ScanJob
import json
import logging


# simple in memory job queue and status tracker
class JobManager:
    def __init__(self):
        self.jobs: Dict[str, dict] = {}
        self.lock = threading.Lock()

    def submit_job(self, func, *args, user_project=None, parameters=None, **kwargs) -> str:
        job_id = str(uuid.uuid4())
        # Save job to DB
        db = SessionLocal()
        job = ScanJob(job_id=job_id, user_project=user_project, parameters=json.dumps(parameters) if parameters else None, status="pending")
        db.add(job)
        db.commit()
        db.close()
        self.jobs[job_id] = {"status": "pending", "result": None}
        logging.info(f"[job_id={job_id}] Submitted scan job. user_project={user_project} parameters={parameters}")
        thread = threading.Thread(target=self._run_job, args=(job_id, func, args, kwargs, user_project, parameters))
        thread.start()
        return job_id

    def _run_job(self, job_id, func, args, kwargs, user_project, parameters):
        db = SessionLocal()
        try:
            # Update status to running
            job = db.query(ScanJob).filter(ScanJob.job_id == job_id).first()
            if job:
                job.status = "running"
                db.commit()
            with self.lock:
                self.jobs[job_id]["status"] = "running"
            logging.info(f"[job_id={job_id}] Started scan job.")
            result = func(*args, **kwargs)
            # Update status to completed
            scan_stats = result.get("count") if isinstance(result, dict) else None
            if job:
                job.status = "completed"
                job.result_file = result.get("file")
                job.scan_stats = json.dumps(scan_stats) if scan_stats is not None else None
                job.finished_at = job.finished_at or None
                db.commit()
            with self.lock:
                self.jobs[job_id]["status"] = "completed"
                self.jobs[job_id]["result"] = result
            logging.info(f"[job_id={job_id}] Completed scan job. stats={scan_stats}")
        except Exception as e:
            if job:
                job.status = "failed"
                job.error = str(e)
                db.commit()
            with self.lock:
                self.jobs[job_id]["status"] = "failed"
                self.jobs[job_id]["result"] = str(e)
            logging.error(f"[job_id={job_id}] Scan job failed: {e}")
        finally:
            db.close()

    def get_status(self, job_id) -> dict:
        db = SessionLocal()
        job = db.query(ScanJob).filter(ScanJob.job_id == job_id).first()
        db.close()
        if job:
            stats = None
            if job.scan_stats:
                try:
                    stats = json.loads(job.scan_stats)
                except Exception:
                    stats = job.scan_stats
            return {
                "job_id": job.job_id,
                "status": job.status,
                "result_file": job.result_file,
                "scan_stats": stats,
                "error": job.error,
                "created_at": str(job.created_at),
                "finished_at": str(job.finished_at) if job.finished_at else None
            }
        return {"status": "not_found", "result": None}