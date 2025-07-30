import os
import re
import yaml
from typing import List, Dict

def extract_containers_and_images(file_path: str) -> List[Dict[str, str]]:
    """
    Extract container names and images from Docker Compose, Swarm, or Dockerfile.
    Returns a list of dicts: [{"name": ..., "image": ...}, ...]
    """
    containers = []
    filename = os.path.basename(file_path).lower()
    try:
        if filename.endswith(('.yml', '.yaml')):
            with open(file_path, 'r') as f:
                data = yaml.safe_load(f)
            # Compose/Swarm: look for 'services'
            if isinstance(data, dict) and 'services' in data:
                for name, svc in data['services'].items():
                    image = svc.get('image')
                    containers.append({"name": name, "image": image})
        elif (
            filename == 'dockerfile' or
            filename.endswith('.dockerfile') or
            'dockerfile' in filename
        ):
            with open(file_path, 'r') as f:
                content = f.read()
            # Find all FROM instructions (multi-stage, with optional AS)
            images = re.findall(r'^FROM\s+([\w./:-]+)', content, re.MULTILINE | re.IGNORECASE)
            for idx, image in enumerate(images):
                containers.append({"image": image})
        else:
            raise ValueError("Unsupported file type for container extraction.")
    except Exception as e:
        containers.append({"error": str(e)})
    return containers 