import pytest
from fastapi.testclient import TestClient
from src.main import app

client = TestClient(app)

def test_health_check():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}

def test_full_scan_async_submission():
    resp = client.post("/scan/full/async", json={"user_project": "testproj"})
    assert resp.status_code == 200
    data = resp.json()
    assert "job_id" in data
    assert data["status"] == "submitted"

def test_specific_scan_async_submission():
    resp = client.post("/scan/specific/async", json={"targets": ["alpine"], "user_project": "testproj"})
    assert resp.status_code == 200
    data = resp.json()
    assert "job_id" in data
    assert data["status"] == "submitted"

def test_scan_history():
    resp = client.get("/scan/history?user_project=testproj")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

def test_job_status_not_found():
    resp = client.get("/scan/job/doesnotexist")
    assert resp.status_code == 200
    assert resp.json()["status"] == "not_found"
