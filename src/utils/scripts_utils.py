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