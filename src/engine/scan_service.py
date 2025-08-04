# src/engine/scan_service.py
"""
ScanService: Shared logic for scan orchestration, image selection, and result formatting.
"""
import docker
from engine import scan_engine
from utils.scripts_utils import calculate_vulnerability_stats

class ScanService:
    def __init__(self):
        self.docker_client = docker.from_env()

    def get_unique_images(self, targets=None):
        images = self.docker_client.images.list()
        unique_images = {}
        for image in images:
            if image.tags:
                for tag in image.tags:
                    repo, version = tag.split(":") if ":" in tag else (tag, "latest")
                    if (targets is None and repo not in unique_images) or (targets and repo in targets):
                        if repo not in unique_images or unique_images[repo]["created"] < image.attrs["Created"]:
                            unique_images[repo] = {"tag": tag, "created": image.attrs["Created"]}
        return unique_images

    def scan_images(self, unique_images):
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
            scan_results.append({"image": tag, "result": result})
            scan_stats.append(calculate_vulnerability_stats(result, tag))
        return scan_results, scan_stats
