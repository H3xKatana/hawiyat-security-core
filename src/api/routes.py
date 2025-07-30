# src/api/routes.py
from fastapi import APIRouter, Response, Body
from api.schemas import ScanRequest, ScanResult
from engine import scan_engine
import json
import os
from utils.extract_containers import extract_containers_and_images

router = APIRouter()

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
    json_bytes = json.dumps(result, indent=2).encode("utf-8")
    headers = {"Content-Disposition": "attachment; filename=scan-result.json"}
    return Response(content=json_bytes, media_type="application/json", headers=headers)

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