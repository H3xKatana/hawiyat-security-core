
# Hawiyat Security Engine

The Hawiyat Security Engine provides a REST API for security scanning of various resources using Trivy. It supports scanning container images, codebases, docker-compose files, Kubernetes manifests, Helm charts, and both local and remote repositories. The API is designed to be modular and extensible, with support for advanced Trivy features such as SBOM generation, compliance checks, secret scanning, and license scanning.

## Installation & Usage

### 1. Build the Docker Image

From the project root 

```sh
docker build -t hawiyat-security-engine .
```

### 2. Run the API (Development Mode)

For hot-reloading and local code mounting, use Docker Compose:

```sh
docker compose up --build
```

### Health Check

* **GET `/health`**

  * **Description**: Returns API health status.
  * **Response**: `{ "status": "ok" }`

#### ✅ Example cURL Request:

```bash
curl -X GET http://localhost:8000/health
```


### 3. Run the API (Production Mode)

```sh
#will be provided later
```

---

## API Documentation

Once the API is running, visit:

```
http://localhost:8000/docs
```

for the full OpenAPI/Swagger documentation and to try out all endpoints interactively.

---
