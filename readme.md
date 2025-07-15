# Hawiyat Security Engine API Documentation

## Overview
The Hawiyat Security Engine provides a REST API for security scanning of various resources using Trivy. It supports scanning container images, codebases, docker-compose files, Kubernetes manifests, Helm charts, and both local and remote repositories. The API is designed to be modular and extensible, with support for advanced Trivy features such as SBOM generation, compliance checks, secret scanning, and license scanning.

---

## API Endpoints

### Health Check
- **GET** `/health`
  - **Description:** Returns API health status.
  - **Response:** `{ "status": "ok" }`

### Scan Resource
- **POST** `/scan`
  - **Description:** Scan a resource (image, codebase, compose, repo, k8s, helm) with optional advanced options.
  - **Request Body:**
    - `type` (string, required): One of `image`, `codebase`, `compose`, `repo`, `k8s`, `helm`.
    - `target` (string, required): Resource to scan (image name, path, file, repo URL, etc.).
    - `sbom` (bool, optional): Generate SBOM if true. Default: false.
    - `compliance` (string, optional): Compliance standard to check (e.g., `CIS`).
    - `secrets` (bool, optional): Enable secret scanning if true. Default: false.
    - `license` (bool, optional): Enable license scanning if true. Default: false.
    - `branch` (string, optional): Branch name for repo scan.
    - `tag` (string, optional): Tag name for repo scan.
    - `commit` (string, optional): Commit hash for repo scan.
  - **Response:**
    - Returns a downloadable JSON file (`scan-result.json`) with the scan results.

#### Example Request
```json
POST /scan
{
  "type": "image",
  "target": "nginx:latest",
  "sbom": true,
  "secrets": true
}
```

#### Example Response
- HTTP 200
- Header: `Content-Disposition: attachment; filename=scan-result.json`
- Body: JSON scan result

---

## Supported Scan Types & Use Cases

### 1. Container Image
- **type:** `image`
- **target:** Docker/OCI image name (e.g., `nginx:latest`)
- **Example:**
  ```json
  { "type": "image", "target": "nginx:latest" }
  ```
- **Options:** `sbom`, `compliance`, `secrets`, `license`

### 2. Codebase (Filesystem)
- **type:** `codebase`
- **target:** Path to local directory (e.g., `/app/src`)
- **Example:**
  ```json
  { "type": "codebase", "target": "/app/src", "secrets": true }
  ```
- **Options:** `sbom`, `compliance`, `secrets`, `license`

### 3. Docker Compose File
- **type:** `compose`
- **target:** Path to `docker-compose.yml`
- **Example:**
  ```json
  { "type": "compose", "target": "docker-compose.yml" }
  ```
- **Options:** `sbom`, `compliance`, `secrets`, `license`

### 4. Repository (Local or Remote)
- **type:** `repo`
- **target:** Local path or remote URL (e.g., `https://github.com/example/repo.git`)
- **Example:**
  ```json
  { "type": "repo", "target": "https://github.com/example/repo.git", "branch": "main", "secrets": true }
  ```
- **Options:** `sbom`, `compliance`, `secrets`, `license`, `branch`, `tag`, `commit`

### 5. Kubernetes Manifest
- **type:** `k8s`
- **target:** Path to manifest file (e.g., `deployment.yaml`)
- **Example:**
  ```json
  { "type": "k8s", "target": "deployment.yaml" }
  ```
- **Options:** `sbom`, `compliance`, `secrets`, `license`

### 6. Helm Chart
- **type:** `helm`
- **target:** Path to chart directory (e.g., `/charts/mychart`)
- **Example:**
  ```json
  { "type": "helm", "target": "/charts/mychart" }
  ```
- **Options:** `sbom`, `compliance`, `secrets`, `license`

---

## Advanced Options

- **sbom**: If true, Trivy will generate a Software Bill of Materials (SBOM) for the target.
- **compliance**: Specify a compliance standard (e.g., `CIS`) to check against.
- **secrets**: If true, enables secret scanning.
- **license**: If true, enables license scanning.
- **branch/tag/commit**: For `repo` scans, specify a branch, tag, or commit to scan.

---

## Error Handling
- If a scan fails, the JSON result will include `success: false` and an `error` message.

---

## Example Use Cases

### Scan a Docker Image for Vulnerabilities and Secrets
```json
{
  "type": "image",
  "target": "alpine:3.18.4",
  "secrets": true
}
```

### Scan a Local Codebase for Compliance
```json
{
  "type": "codebase",
  "target": "/app/src",
  "compliance": "CIS"
}
```

### Scan a Remote GitHub Repo (main branch) for Licenses
```json
{
  "type": "repo",
  "target": "https://github.com/example/repo.git",
  "branch": "main",
  "license": true
}
```

### Scan a Kubernetes Manifest
```json
{
  "type": "k8s",
  "target": "deployment.yaml"
}
```

---

## Notes
- All scan results are returned as a downloadable JSON file (`scan-result.json`).
- The API is designed for easy integration with CI/CD pipelines and deployment tools like Dokploy.
- For private repositories, ensure the appropriate environment variables (e.g., `GITHUB_TOKEN`, `GITLAB_TOKEN`) are set in the container.
- For more details on Trivy's scanning capabilities, see the [Trivy documentation](https://trivy.dev/v0.56/docs/). 

---

Absolutely! Here’s a step-by-step guide to run and test your Hawiyat Security Engine project.

---

## 1. **Build the Docker Image**

From your project root (where the Dockerfile is):

```sh
docker build -t hawiyat-security-engine .
```

---

## 2. **Run the API in Development Mode (with Live Code Mounting)**

If you want hot-reloading and to mount your local code, use a `docker-compose.yml` like this:

```yaml
version: "3.9"
services:
  api:
    build:
      context: .
      dockerfile: Dockerfile
    volumes:
      - ./src:/app/src
      - ./requirements.txt:/app/requirements.txt
    ports:
      - "8000:8000"
    command: uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
    environment:
      - PYTHONUNBUFFERED=1
```

Then run:

```sh
<code_block_to_apply_changes_from>
```

---

## 3. **Run the API in Production Mode**

If you just want to run the built image:

```sh
docker run --rm -p 8000:8000 hawiyat-security-engine
```

---

## 4. **Test the API**

### Health Check

```sh
curl http://localhost:8000/health
```

Should return:
```json
{"status": "ok"}
```

---

### Example Scan Request

#### Scan a Docker Image

```sh
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"type": "image", "target": "alpine:3.18.4"}' \
  -o scan-result.json
```

#### Scan a Remote Repo (main branch, with secrets scanning)

```sh
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"type": "repo", "target": "https://github.com/aquasecurity/trivy-ci-test", "branch": "main", "secrets": true}' \
  -o scan-result.json
```

#### Scan a Local Codebase

If you want to scan a local directory, make sure it’s available inside the container (mount it or copy it in).

---

## 5. **View the Results**

The scan result will be saved as `scan-result.json`. Open it in your favorite editor or viewer.

---

## 6. **Troubleshooting**

- If you get permission errors, ensure Docker has access to the directories you want to scan.
- For private repos, set `GITHUB_TOKEN` or `GITLAB_TOKEN` as environment variables in your container.
- If you need to install additional dependencies, update your `requirements.txt` and rebuild.

---

Let me know if you encounter any issues or want to test a specific use case! 