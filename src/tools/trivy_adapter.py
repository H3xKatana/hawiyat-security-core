# src/tools/trivy_adapter.py
from .base import SecurityToolAdapter
import subprocess
import json

class TrivyAdapter(SecurityToolAdapter):
    def run_scan(self, args, expect_json=True) -> dict:
        try:
            cmd = ["trivy"] + args + (["--format", "json"] if expect_json and "--format" not in args else [])
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )
            if result.returncode != 0:
                return {"success": False, "error": result.stderr}
            if expect_json:
                try:
                    output = json.loads(result.stdout)
                    return {"success": True, "result": output}
                except json.JSONDecodeError:
                    return {"success": False, "error": "Failed to parse Trivy output as JSON."}
            else:
                return {"success": True, "result": result.stdout}
        except Exception as e:
            return {"success": False, "error": str(e)} 