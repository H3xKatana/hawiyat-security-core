# src/engine/scan_engine.py
# Placeholder for scan orchestration logic 
from tools.trivy_adapter import TrivyAdapter
import tempfile
import shutil
import os
import subprocess
from api.schemas import ScanRequest

# Trivy scan types and their corresponding commands
SCAN_TYPE_TO_CMD = {
    'image': lambda target: ["image", target],
    'codebase': lambda target: ["fs", target],
    'compose': lambda target: ["config", "--input", target],
    'repo': lambda target: ["repo", target],  # local or remote repo
    'k8s': lambda target: ["config", "--input", target],
    'helm': lambda target: ["helm", target],
    'sbom': lambda target: ["sbom", target],
}

def scan_target(scan_type: str, target: str, sbom=False, compliance=None, secrets=False, license=False, branch=None, tag=None, commit=None) -> dict:
    adapter = TrivyAdapter()
    try:
        if scan_type not in SCAN_TYPE_TO_CMD:
            return {"success": False, "error": f"Unsupported scan type: {scan_type}"}
        # SBOM generation logic
        if sbom and scan_type != 'sbom':
            with tempfile.NamedTemporaryFile(suffix='.cdx.json', delete=False) as sbom_file:
                sbom_path = sbom_file.name
            try:
                # Generate SBOM in CycloneDX format
                cmd = SCAN_TYPE_TO_CMD[scan_type](target) + ["--format", "cyclonedx", "--output", sbom_path]
                result = adapter.run_scan(cmd, expect_json=False)
                if not os.path.exists(sbom_path):
                    return {"success": False, "error": "SBOM file was not generated."}
                with open(sbom_path, "r") as f:
                    sbom_content = f.read()
                os.remove(sbom_path)
                return {"success": True, "result": sbom_content}
            except Exception as e:
                if os.path.exists(sbom_path):
                    os.remove(sbom_path)
                return {"success": False, "error": str(e)}
        # Normal scan or SBOM scan
        cmd = SCAN_TYPE_TO_CMD[scan_type](target)
        # Add advanced options
        if compliance:
            cmd += ["--compliance", compliance]
        if secrets:
            cmd += ["--scanners", "secret"]
        if license:
            cmd += ["--scanners", "license"]
        if scan_type == 'repo':
            if branch:
                cmd += ["--branch", branch]
            if tag:
                cmd += ["--tag", tag]
            if commit:
                cmd += ["--commit", commit]
        return adapter.run_scan(cmd)
    except Exception as e:
        return {"success": False, "error": str(e)} 