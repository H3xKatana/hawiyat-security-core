# src/api/schemas.py
# Placeholder for Pydantic models for scan requests and responses 
from pydantic import BaseModel, Field
from typing import Any, Optional, Literal

class ScanRequest(BaseModel):
    type: Literal['image', 'codebase', 'compose', 'repo', 'k8s', 'helm'] = Field(..., description="Type of scan target")
    target: str  # e.g., image name, directory, file, repo URL, etc.
    sbom: Optional[bool] = Field(False, description="Generate SBOM if True")
    compliance: Optional[str] = Field(None, description="Compliance standard to check (e.g., 'CIS')")
    secrets: Optional[bool] = Field(False, description="Enable secret scanning if True")
    license: Optional[bool] = Field(False, description="Enable license scanning if True")
    branch: Optional[str] = Field(None, description="Branch name for repo scan")
    tag: Optional[str] = Field(None, description="Tag name for repo scan")
    commit: Optional[str] = Field(None, description="Commit hash for repo scan")

class ScanResult(BaseModel):
    success: bool
    result: Optional[Any] = None  # Raw or parsed scan result
    error: Optional[str] = None 