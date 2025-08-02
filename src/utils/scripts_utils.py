import os
import json
import datetime

def save_scan_result(scan_type, target, result, base_dir="scans"):
    """
    Save the scan result in a directory structure based on the scan type and timestamp.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    month_folder = datetime.datetime.now().strftime("%Y-%m")
    scan_folder = os.path.join(base_dir, scan_type, month_folder)
    os.makedirs(scan_folder, exist_ok=True)

    scan_filename = os.path.join(scan_folder, f"scan_{timestamp}.json")
    with open(scan_filename, "w") as f:
        json.dump(result, f, indent=4)

    return scan_filename

def save_full_scan_results(scan_results, base_dir="scans"):
    """
    Save all full scan results in a single file.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    month_folder = datetime.datetime.now().strftime("%Y-%m")
    scan_folder = os.path.join(base_dir, month_folder)
    os.makedirs(scan_folder, exist_ok=True)

    scan_filename = os.path.join(scan_folder, f"full_scan_{timestamp}.json")
    with open(scan_filename, "w") as f:
        json.dump(scan_results, f, indent=4)

    return scan_filename

def calculate_vulnerability_stats(scan_results):
    """
    Calculate the number of vulnerabilities by severity (LOW, MEDIUM, HIGH, CRITICAL).
    """
    severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

    for result in scan_results:
        if "vulnerabilities" in result:
            for vuln in result["vulnerabilities"]:
                severity = vuln.get("Severity", "").upper()
                if severity in severity_counts:
                    severity_counts[severity] += 1

    total_vulnerabilities = sum(severity_counts.values())

    return {
        "severity_counts": severity_counts,
        "total_vulnerabilities": total_vulnerabilities
    }