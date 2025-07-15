# src/api/routes.py
from fastapi import APIRouter, Response
from api.schemas import ScanRequest, ScanResult
from engine import scan_engine
import json

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

# Placeholder for scan endpoints 