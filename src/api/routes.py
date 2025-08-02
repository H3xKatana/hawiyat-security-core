# src/api/routes.py
from fastapi import APIRouter, Response, Body, Query
from api.schemas import ScanRequest, ScanResult
from engine import scan_engine
import json
import os
from utils.extract_containers import extract_containers_and_images 
from utils.scripts_utils import save_scan_result, save_full_scan_results , calculate_vulnerability_stats
from datetime import datetime
import docker
import glob
import sys




router = APIRouter()

SCAN_RESULTS_DIR = "scans"
SBOM_DIR = "sbom"
os.makedirs(SCAN_RESULTS_DIR, exist_ok=True)
os.makedirs(SBOM_DIR, exist_ok=True)

docker_client = docker.from_env()

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

@router.get("/scans")
def get_scans(
    month: str = Query(None, description="Filter scans by month in YYYY-MM format"),
    limit: int = Query(10, description="Limit the number of results returned"),
    offset: int = Query(0, description="Offset for pagination")
):
    try:
        scans = []
        base_dir = os.path.join(SCAN_RESULTS_DIR, month) if month else SCAN_RESULTS_DIR
        if os.path.exists(base_dir):
            for root, _, files in os.walk(base_dir):
                for file in files:
                    if file.endswith(".json"):
                        scans.append(os.path.join(root, file))

        scans = sorted(scans, reverse=True)[offset:offset + limit]
        return {"success": True, "scans": scans}

    except Exception as e:
        return {"success": False, "error": str(e)}

@router.get("/scans/{scan_id}")
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
        images = docker_client.images.list()
        unique_images = {}

        # Identify the newest version of each image
        for image in images:
            if image.tags:
                for tag in image.tags:
                    repo, version = tag.split(":") if ":" in tag else (tag, "latest")
                    if repo not in unique_images or unique_images[repo]["created"] < image.attrs["Created"]:
                        unique_images[repo] = {"tag": tag, "created": image.attrs["Created"]}

        scan_results = []
        scan_stats = []
        for repo, image_info in unique_images.items():
            tag = image_info["tag"]
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
            
            scan_results.append({
                "image": tag,
                "result": result
            })
            
            scan_stats.append(calculate_vulnerability_stats(result,tag))


        scan_filename = save_full_scan_results(scan_results)

        return {"success": True,"count": scan_stats , "file": scan_filename}

    except Exception as e:
        return {"success": False, "error": str(e)}

@router.post("/scan/specific")
def specific_scan(targets: list[str] = Body(..., embed=True)):
    """
    Trigger a scan for a list of specific images, scanning only the newest version of each image.
    """
    try:
        images = docker_client.images.list()
        unique_images = {}

        # Identify the newest version of each image in the targets
        for image in images:
            if image.tags:
                for tag in image.tags:
                    repo, version = tag.split(":") if ":" in tag else (tag, "latest")
                    if repo in targets and (repo not in unique_images or unique_images[repo]["created"] < image.attrs["Created"]):
                        unique_images[repo] = {"tag": tag, "created": image.attrs["Created"]}

        scan_results = []

        for repo, image_info in unique_images.items():
            tag = image_info["tag"]
            result = scan_engine.scan_target(
                scan_type="image",
                target=tag,
                sbom=True,
                compliance=False,
                secrets=True,
                license=False,
                branch=None,
                tag=None,
                commit=None
            )
            scan_file = save_scan_result("image", tag, result)
            scan_results.append({"target": tag, "result": result, "file": scan_file})

        return {"success": True, "results": scan_results}

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
