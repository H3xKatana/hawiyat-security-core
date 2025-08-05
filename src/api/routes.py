# src/api/routes.py
from fastapi import APIRouter, Response, Body, Query ,Request
from api.schemas import ScanRequest, ScanResult
from engine import scan_engine
from engine.scan_service import ScanService
from engine.job_manager import JobManager
import json
import os
from utils.extract_containers import extract_containers_and_images 
from utils.scripts_utils import save_scan_result, save_full_scan_results , calculate_vulnerability_stats
from datetime import datetime
import docker
import glob
import sys
import logging
from fastapi.responses import FileResponse
import tempfile
import subprocess
import shutil
import pathlib

router = APIRouter()
WEBHOOK_FILE_PATH = "/app/webhook.txt"
SCAN_RESULTS_DIR = "scans"
SBOM_DIR = "sbom"
os.makedirs(SCAN_RESULTS_DIR, exist_ok=True)
os.makedirs(SBOM_DIR, exist_ok=True)

docker_client = docker.from_env()
scan_service = ScanService()
job_manager = JobManager()

@router.post(
    "/scan/full/async",
    summary="Submit a full scan job (async)",
    response_description="Job ID and submission status",
    tags=["Scan Jobs"],
    response_model=dict,
    responses={
        200: {"description": "Job submitted successfully"},
        500: {"description": "Internal server error"}
    },
)
def full_scan_async(user_project: str = Body(None, embed=True)):
    """
    Submit a full scan job (async). Returns a job ID.
    """
    job_id = job_manager.submit_job(_run_full_scan_job, user_project=user_project, parameters={"type": "full"})
    return {"job_id": job_id, "status": "submitted"}

def _run_full_scan_job():
    unique_images = scan_service.get_unique_images()
    scan_results, scan_stats = scan_service.scan_images(unique_images)
    scan_filename = save_full_scan_results(scan_results)
    return {"count": scan_stats, "file": scan_filename}


@router.post(
    "/scan/specific/async",
    summary="Submit a specific scan job (async)",
    response_description="Job ID and submission status",
    tags=["Scan Jobs"],
    response_model=dict,
    responses={
        200: {"description": "Job submitted successfully"},
        500: {"description": "Internal server error"}
    },
)
def specific_scan_async(tags: list[str] = Body(..., embed=True), user_project: str = Body(None, embed=True)):
    """
    Submit a specific scan job (async) for provided image tags. Returns a job ID.
    """
    job_id = job_manager.submit_job(_run_specific_scan_job, tags, user_project=user_project, parameters={"type": "specific", "tags": tags})
    return {"job_id": job_id, "status": "submitted"}
from engine.db import SessionLocal
from engine.models import ScanJob
@router.get("/scan/history")
def get_scan_history(user_project: str = None, status: str = None, limit: int = 20, offset: int = 0):
    """
    Query scan job history by user/project and/or status.
    """
    db = SessionLocal()
    query = db.query(ScanJob)
    if user_project:
        query = query.filter(ScanJob.user_project == user_project)
    if status:
        query = query.filter(ScanJob.status == status)
    jobs = query.order_by(ScanJob.created_at.desc()).offset(offset).limit(limit).all()
    db.close()
    return [{
        "job_id": job.job_id,
        "user_project": job.user_project,
        "status": job.status,
        "result_file": job.result_file,
        "created_at": str(job.created_at),
        "finished_at": str(job.finished_at) if job.finished_at else None,
        "error": job.error
    } for job in jobs]

def _run_specific_scan_job(tags):
    scan_results = []
    scan_stats = []
    for tag in tags:
        result = scan_engine.scan_target(
            scan_type="image",
            target=tag,
            sbom=False,
            compliance=False,
            secrets=False,
            license=False,
            branch=None,
            tag=None,
            commit=None
        )
        scan_results.append({"image": tag, "result": result})
        scan_stats.append(calculate_vulnerability_stats(result, tag))
    scan_filename = save_full_scan_results(scan_results)
    return {"count": scan_stats, "file": scan_filename}

@router.get(
    "/scan/job/{job_id}",
    summary="Get scan job status and result",
    response_description="Scan job status, result file, and stats",
    tags=["Scan Jobs"],
    response_model=dict,
    responses={
        200: {"description": "Job status and result"},
        404: {"description": "Job not found"},
        500: {"description": "Internal server error"}
    },
)
def get_scan_job_status(job_id: str):
    """
    Get the status and result of a scan job by job ID.
    """
    return job_manager.get_status(job_id)

@router.get("/health")
def health_check():
    return {"status": "ok"}

@router.post("/scan")
def scan(request: ScanRequest):
    result = scan_engine.scan_target(
        scan_type=request.type,
        target=request.target,
        sbom=request.sbom,
        compliance=request.compliance,
        secrets=request.secrets,
        license=request.license,
        branch=request.branch,
        tag=request.tag,
        commit=request.commit
    )

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    month_folder = datetime.now().strftime("%Y-%m")
    scan_folder = os.path.join(SCAN_RESULTS_DIR, month_folder)
    os.makedirs(scan_folder, exist_ok=True)

    scan_filename = os.path.join(scan_folder, f"scan_{timestamp}.json")
    with open(scan_filename, "w") as f:
        json.dump(result, f, indent=4)

    sbom_filename = None
    if request.sbom:
        sbom_folder = os.path.join(SBOM_DIR, month_folder)
        os.makedirs(sbom_folder, exist_ok=True)
        sbom_filename = os.path.join(sbom_folder, f"sbom_{timestamp}.json")
        with open(sbom_filename, "w") as f:
            json.dump(result.get("result"), f, indent=4)

    return {"success": True, "scan_file": scan_filename, "sbom_file": sbom_filename}

@router.get(
    "/scan/history",
    summary="Query scan job history",
    response_description="List of scan jobs filtered by user/project and status",
    tags=["Scan Jobs"],
    response_model=list,
    responses={
        200: {"description": "Scan job history"},
        500: {"description": "Internal server error"}
    },
)
def get_scan_history(user_project: str = None, status: str = None, limit: int = 20, offset: int = 0):
    """
    Query scan job history by user/project and/or status.
    """
    db = SessionLocal()
    query = db.query(ScanJob)
    if user_project:
        query = query.filter(ScanJob.user_project == user_project)
    if status:
        query = query.filter(ScanJob.status == status)
    jobs = query.order_by(ScanJob.created_at.desc()).offset(offset).limit(limit).all()
    db.close()
    return [{
        "job_id": job.job_id,
        "user_project": job.user_project,
        "status": job.status,
        "result_file": job.result_file,
        "created_at": str(job.created_at),
        "finished_at": str(job.finished_at) if job.finished_at else None,
        "error": job.error
    } for job in jobs]
def get_scan(scan_id: str):
    """
    Retrieve the content of a specific scan file by its ID.
    """
    try:
        # Search for the scan file in all subdirectories of SCAN_RESULTS_DIR
        for root, _, files in os.walk(SCAN_RESULTS_DIR):
            for file in files:
                if file == scan_id:
                    scan_path = os.path.join(root, file)
                    with open(scan_path, "r") as f:
                        scan_content = json.load(f)
                    return {"success": True, "scan": scan_content}

        return {"success": False, "error": "Scan file not found."}

    except Exception as e:
        return {"success": False, "error": str(e)}

@router.get("/scan/latest")
def get_latest_scans():
    """
    Retrieve all scan files from the latest month.
    """
    try:
        # Determine the latest month folder
        all_months = [d for d in os.listdir(SCAN_RESULTS_DIR) if os.path.isdir(os.path.join(SCAN_RESULTS_DIR, d))]
        if not all_months:
            return {"success": False, "error": "No scans available."}

        latest_month = sorted(all_months, reverse=True)[0]
        latest_month_path = os.path.join(SCAN_RESULTS_DIR, latest_month)

        # Collect all scan files in the latest month folder
        scans = []
        for root, _, files in os.walk(latest_month_path):
            for file in files:
                if file.endswith(".json"):
                    scans.append(os.path.join(root, file))

        return {"success": True, "latest_month": latest_month, "scans": scans}

    except Exception as e:
        return {"success": False, "error": str(e)}

@router.post("/scan/full")
def full_scan():
    """
    Trigger a full scan of all unique images on the host machine, scanning only the newest version of each image.
    Store all results in a single file.
    """
    try:
        unique_images = scan_service.get_unique_images()
        scan_results, scan_stats = scan_service.scan_images(unique_images)
        scan_filename = save_full_scan_results(scan_results)
        return {"success": True, "count": scan_stats, "file": scan_filename}
    except Exception as e:
        return {"success": False, "error": str(e)}

@router.post("/scan/specific")
def specific_scan(targets: list[str] = Body(..., embed=True)):
    """
    Trigger a scan for a list of specific images, scanning only the newest version of each image.
    Store all results in a single file.
    """
    try:
        unique_images = scan_service.get_unique_images(targets)
        scan_results, scan_stats = scan_service.scan_images(unique_images)
        scan_filename = save_full_scan_results(scan_results)
        return {"success": True, "count": scan_stats, "file": scan_filename}
    except Exception as e:
        return {"success": False, "error": str(e)}



@router.post("/extract")
def extract(file_path: str = Body(..., embed=True)):
    """
    Extract container names and images from a given file (compose, swarm, or Dockerfile).
    """
    if not os.path.exists(file_path):
        return {"success": False, "error": f"File not found: {file_path}"}
    result = extract_containers_and_images(file_path)
    return {"success": True, "containers": result}

@router.post("/scan/docker")
def scan_docker_file(file_path: str = Body(..., embed=True)):
    """
    Extracts images from a Dockerfile, Compose, or Swarm file and scans each one,
    returning only the vulnerabilities found.
    """
    if not os.path.exists(file_path):
        return {"success": False, "error": f"File not found: {file_path}"}
    
    containers_info = extract_containers_and_images(file_path)
    
    if not containers_info or "error" in containers_info[0]:
        return {"success": False, "error": "Failed to extract images from file.", "details": containers_info[0].get("error", "Unknown extraction error")}

    images_to_scan = {info.get("image") for info in containers_info if info.get("image")}

    if not images_to_scan:
        return {"success": False, "error": "No images found to scan in the provided file."}

    scan_results = {}
    for image in images_to_scan:
        result = scan_engine.scan_target(scan_type='image', target=image)
        
        # Simplify the output to focus on vulnerabilities
        if result.get("success"):
            trivy_report = result.get("result", {})
            vulnerabilities = []
            if isinstance(trivy_report, dict) and "Results" in trivy_report:
                for res in trivy_report.get("Results", []):
                    if "Vulnerabilities" in res:
                        vulnerabilities.extend(res["Vulnerabilities"])
            
            scan_results[image] = {
                "success": True,
                "vulnerabilities": vulnerabilities
            }
        else:
            scan_results[image] = {
                "success": False,
                "error": result.get("error", "Unknown scan error")
            }

    return {"success": True, "results": scan_results}

@router.get("/target/list")
def list_targets():
    """Retrieve all available Docker images."""
    try:
        images = docker_client.images.list()
        image_tags = []
        
        for image in images:
            if image.tags:
                image_tags.extend(image.tags)
            else:
                image_tags.append(f"<none>:{image.short_id}")
        
        return {
            "success": True,
            "images": list(dict.fromkeys(image_tags))
        }
    except Exception as e:
        return {"success": False, "error": "Failed to retrieve Docker images"}
    
@router.get("/target/local-git")
def list_local_git_repos():
    """
    Scan the /etc/hawiyat directory for all .git repositories and return their paths.
    """
    try:
        base_dir = "/etc/hawiyat"
        git_repos = glob.glob(f"{base_dir}/**/.git", recursive=True)
        
        # Format the paths to return the parent directory of the .git folder
        repo_paths = [os.path.dirname(repo) for repo in git_repos]

        return {"success": True, "repositories": repo_paths}

    except Exception as e:
        return {"success": False, "error": str(e)}

@router.post(
    "/scan/sbom",
    summary="Generate SBOM for a specific image, tag, or repo",
    response_description="SBOM file (CycloneDX or SPDX)",
    tags=["SBOM"],
    responses={
        200: {"description": "SBOM file returned"},
        400: {"description": "Invalid input or scan error"},
        500: {"description": "Internal server error"}
    },
)
def generate_sbom(
    target: str = Body(..., embed=True),
    scan_type: str = Body("image", embed=True),
    format: str = Body("cyclonedx", embed=True)
):
    """
    Generate an SBOM for a specific Docker image (by tag), repository, or image name using Trivy.
    scan_type can be 'image', 'repo', or other supported types.
    format can be 'cyclonedx' (default) or 'spdx'.
    Returns the SBOM as a downloadable file.
    """
    try:
        # Use scan_engine to generate SBOM file
        with tempfile.NamedTemporaryFile(suffix=f'.{format}.json', delete=False) as sbom_file:
            sbom_path = sbom_file.name
        result = scan_engine.scan_target(scan_type=scan_type, target=target, sbom=True)
        if result.get("success"):
            # Write SBOM content to file
            with open(sbom_path, "w", encoding="utf-8") as f:
                f.write(result.get("result"))
            filename = f"sbom_{scan_type}_{target.replace(':', '_')}.{format}.json"
            return FileResponse(sbom_path, filename=filename, media_type="application/json")
        else:
            return {"success": False, "error": result.get("error", "SBOM generation failed")}
    except Exception as e:
        return {"success": False, "error": str(e)}

@router.delete(
    "/scan/job/{job_id}",
    summary="Delete a scan job and its associated result file",
    response_description="Job deletion status",
    tags=["Scan Jobs"],
    response_model=dict,
    responses={
        200: {"description": "Job deleted successfully"},
        404: {"description": "Job not found"},
        500: {"description": "Internal server error"}
    },
)
def delete_scan_job(job_id: str):
    """
    Delete a scan job from the database and remove its associated result file (if any).
    """
    db = SessionLocal()
    job = db.query(ScanJob).filter(ScanJob.job_id == job_id).first()
    if not job:
        db.close()
        return {"success": False, "error": "Job not found"}
    # Remove result file if it exists
    if job.result_file and os.path.exists(job.result_file):
        try:
            os.remove(job.result_file)
        except Exception as e:
            db.close()
            return {"success": False, "error": f"Failed to delete result file: {e}"}
    db.delete(job)
    db.commit()
    db.close()
    return {"success": True, "message": f"Job {job_id} and associated file deleted."}



@router.post(
    "/scan/repo/async",
    summary="Submit a git repo scan job (async) for vuln scan ",
    response_description="Job ID and submission status",
    tags=["Repository Scans", "Scan Jobs"],
    response_model=dict,
    responses={
        200: {"description": "Job submitted successfully"},
        500: {"description": "Internal server error"}
    },
)
def scan_git_repo_async(
    repo_url: str = Body(..., embed=True, description="Remote repo URL (https) or local path"),
    
    branch: str = Body(None, embed=True, description="Branch name (optional)"),
    tag: str = Body(None, embed=True, description="Tag name (optional)"),
    commit: str = Body(None, embed=True, description="Commit hash (optional)"),
    token: str = Body(None, embed=True, description="Access token for private repos (optional)"),
    user_project: str = Body(None, embed=True, description="User/project identifier (optional)")
):
    """
    Submit a git repo scan job (async) for vuln scan and/or SBOM. Returns a job ID.
    """
    logging.info(f"Submitting repo scan job for {repo_url} on branch {branch}, tag {tag}, commit {commit}")
    job_id = job_manager.submit_job(
        _run_repo_scan_job,
        repo_url, branch, tag, commit, token, user_project,
        user_project=user_project,
        parameters={
            "type": "repo",
            "repo_url": repo_url,
            
            "branch": branch,
            "tag": tag,
            "commit": commit,
            "token": token
        }
    )
    return {"job_id": job_id, "status": "submitted"}

def _run_repo_scan_job(repo_url, branch, tag, commit, token, user_project=None):
    """
    Job function to scan a git repo and save results (and SBOM if requested).
    """
    if branch == "string" or branch is None:
        branch = "main"
    tmp_dir = None
    try:
        env = os.environ.copy()
        if token:
            env["GITHUB_TOKEN"] = token
        # If remote repo, clone to temp dir
        is_remote = repo_url.startswith("http://") or repo_url.startswith("https://") or repo_url.startswith("git@")
        scan_path = repo_url
        if is_remote:
            tmp_dir = tempfile.mkdtemp(prefix="repo_scan_")
            clone_cmd = ["git", "clone", repo_url, tmp_dir]
            if branch:
                clone_cmd += ["--branch", branch]
            subprocess.run(clone_cmd, check=True)
            scan_path = tmp_dir
            logging.info(f"Cloned repo to temporary directory: {scan_path}")
        scan_result = scan_engine.scan_target(
            scan_type="repo",
            target=scan_path,
            branch=branch,
            tag=tag,
            commit=commit
        )
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        month_folder = datetime.now().strftime("%Y-%m")
        scan_folder = os.path.join(SCAN_RESULTS_DIR, month_folder)
        os.makedirs(scan_folder, exist_ok=True)
        scan_filename = os.path.join(scan_folder, f"repo_scan_{timestamp}.json")
        with open(scan_filename, "w") as f:
            json.dump(scan_result, f, indent=4)
        logging.info(f'file: {scan_filename}, scan_stats: None, error: {scan_result.get("error")}')
        scan_stats=[]
        scan_stats.append({"repo": repo_url})
        scan_stats.append(calculate_vulnerability_stats(scan_result))
        logging.info(f"Scan completed for {repo_url}. Results saved to {scan_filename} {scan_stats}")
        return {
            "success": True,
            "file": scan_filename,
            "count": scan_stats,
            "error": scan_result.get("error")
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        if tmp_dir and os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)

@router.post(
    "/scan/repo",
    summary="Scan a git repository (remote public/private or local) for vulnerabilities and/or generate SBOM",
    response_description="Scan result and/or SBOM file",
    tags=["Repository Scans"],
    responses={
        200: {"description": "Scan result and/or SBOM file"},
        400: {"description": "Invalid input or scan error"},
        500: {"description": "Internal server error"}
    },
)
def scan_git_repo(
    repo_url: str = Body(..., embed=True, description="Remote repo URL (https) or local path"),
    sbom: bool = Body(False, embed=True, description="Generate SBOM if true"),
    branch: str = Body(None, embed=True, description="Branch name (optional)"),
    tag: str = Body(None, embed=True, description="Tag name (optional)"),
    commit: str = Body(None, embed=True, description="Commit hash (optional)"),
    token: str = Body(None, embed=True, description="Access token for private repos (optional)")
):
    """
    Scan a git repository (remote public/private or local) for vulnerabilities and/or generate SBOM.
    Returns scan result and/or SBOM file as download links.
    """
    try:
        # If token is provided, set env var for Trivy
        env = os.environ.copy()
        if token:
            env["GITHUB_TOKEN"] = token
        # Run vulnerability scan
        scan_result = scan_engine.scan_target(
            scan_type="repo",
            target=repo_url,
            sbom=sbom,
            branch=branch,
            tag=tag,
            commit=commit
        )
        # Save scan result
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        month_folder = datetime.now().strftime("%Y-%m")
        scan_folder = os.path.join(SCAN_RESULTS_DIR, month_folder)
        os.makedirs(scan_folder, exist_ok=True)
        scan_filename = os.path.join(scan_folder, f"repo_scan_{timestamp}.json")
        with open(scan_filename, "w") as f:
            json.dump(scan_result, f, indent=4)

        # If SBOM requested and successful, save SBOM
        sbom_filename = None
        if sbom and scan_result.get("success"):
            sbom_folder = os.path.join(SBOM_DIR, month_folder)
            os.makedirs(sbom_folder, exist_ok=True)
            sbom_filename = os.path.join(sbom_folder, f"repo_sbom_{timestamp}.json")
            # If scan_result["result"] is a string, write as text, else as JSON
            sbom_content = scan_result.get("result")
            if isinstance(sbom_content, str):
                with open(sbom_filename, "w", encoding="utf-8") as f:
                    f.write(sbom_content)
            else:
                with open(sbom_filename, "w", encoding="utf-8") as f:
                    json.dump(sbom_content, f, indent=4)

        response = {"success": scan_result.get("success", False), "scan_file": scan_filename}
        if sbom_filename:
            response["sbom_file"] = sbom_filename
        if not scan_result.get("success"):
            response["error"] = scan_result.get("error", "Scan failed")
        return response
    except Exception as e:
        return {"success": False, "error": str(e)}

def _run_repo_secret_scan_job(repo_url, branch, token, user_project=None):
    """
    Job function to scan a git repo for secrets using Gitleaks and save results.
    """
    tmp_dir = None
    try:
        # Prepare repo for scanning
        is_remote = repo_url.startswith("http://") or repo_url.startswith("https://") or repo_url.startswith("git@")
        if is_remote:
            tmp_dir = tempfile.mkdtemp(prefix="gitleaks_repo_")
            clone_cmd = ["git", "clone", repo_url, tmp_dir]
            env = os.environ.copy()
            if token and "github.com" in repo_url:
                # Insert token into URL for private GitHub
                repo_url_with_token = repo_url.replace("https://", f"https://{token}@")
                clone_cmd = ["git", "clone", repo_url_with_token, tmp_dir]
                if branch :
                    clone_cmd += ["--branch", branch]
            subprocess.run(clone_cmd, check=True)
            scan_path = tmp_dir
            logging.info(f"Cloned repo to temporary directory: {scan_path}")
        else:
            scan_path = repo_url

        # Run Gitleaks
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        month_folder = datetime.now().strftime("%Y-%m")
        scan_folder = os.path.join(SCAN_RESULTS_DIR, month_folder)
        os.makedirs(scan_folder, exist_ok=True)
        result_file = os.path.abspath(os.path.join(scan_folder, f"gitleaks_{timestamp}.json"))
        logging.info(f"Running Gitleaks on {scan_path} with result file {result_file}")
        gitleaks_cmd = ["gitleaks", "detect", "-f","json","-s", scan_path, "--report-path", result_file]
        logging.info(f"Gitleaks command: {' '.join(gitleaks_cmd)}")
        proc = subprocess.run(gitleaks_cmd, capture_output=True, text=True)
        logging.info(f"Gitleaks output: {proc.stdout}")

        # Optionally, load and return the results
        with open(result_file, "r") as f:
            results = json.load(f)
            length_results = len(results)

        # For job_manager: use 'file' for result_file, 'scan_stats' as number of possible leaks
        return {
            "success": True,
            "file": result_file,
            "count": {
            "nbr_possible_leaks": length_results},
            }
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        if tmp_dir and os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)

@router.post(
    "/scan/repo/secrets/async",
    summary="Submit a git repo secret scan job (async) using Gitleaks",
    response_description="Job ID and submission status",
    tags=["Repository Scans", "Scan Jobs", "Secrets"],
    response_model=dict,
    responses={
        200: {"description": "Job submitted successfully"},
        500: {"description": "Internal server error"}
    },
)
def scan_git_repo_secrets_async(
    repo_url: str = Body(..., embed=True, description="Remote repo URL (https) or local path"),
    branch: str = Body(None, embed=True, description="Branch name (optional)"),
    token: str = Body(None, embed=True, description="Access token for private repos (optional)"),
    user_project: str = Body(None, embed=True, description="User/project identifier (optional)")
):
    """
    Submit a git repo secret scan job (async) using Gitleaks. Returns a job ID.
    """
    if branch == "string" or branch is None:
            branch = "main"  # Default branch if not specified
    job_id = job_manager.submit_job(
        _run_repo_secret_scan_job,
        repo_url, branch, token, user_project,
        user_project=user_project,
        parameters={
            "type": "repo_secrets",
            "repo_url": repo_url,
            "branch": branch,
            "token": token
        }
    )
    return {"job_id": job_id, "status": "submitted"}



@router.post("/webhook/config", 
            
        summary="Set a global webhook URL for all jobs",
        tags=["Webhook"],
        responses={
        200: {"description": " submitted successfully"},
        500: {"description": "Internal server error"}},
    )
def configure_webhook(webhook: str = Body(..., embed=True, description="Webhook URL to POST job results")):
    try:
        pathlib.Path(WEBHOOK_FILE_PATH).write_text(webhook.strip())
        return {"success": True, "webhook_url": webhook.strip()}
    except Exception as e:
        return {"success": False, "error": str(e)}

@router.get("/webhook/config", summary="Get the current webhook URL", tags=["Webhook"])
def get_webhook_config():
    """
    Get the currently configured webhook URL.
    """
    try:
        if not os.path.exists(WEBHOOK_FILE_PATH):
            return {"success": False, "error": "Webhook URL not configured"}
        url = pathlib.Path(WEBHOOK_FILE_PATH).read_text().strip()
        return {"success": True, "webhook_url": url}
    except Exception as e:
        return {"success": False, "error": str(e)}
    
@router.post("/webhook/local", summary="Test your local webhook receiver", tags=["Webhook"])
async def test_webhook_receiver(request: Request):
    try:
        data = await request.json()
        logging.info(f"[webhook.local] Received webhook data: {data}")
        return {"success": True, "received": data}
    except Exception as e:
        logging.error(f"[webhook.local] Failed to parse webhook data: {e}")
        return {"success": False, "error": str(e)}
    