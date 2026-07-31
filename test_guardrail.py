import pytest
from fastapi.testclient import TestClient
from app import app, SANDBOX_ROOT
import os

client = TestClient(app)

def test_read_file_benign():
    # Should be allowed
    path = os.path.join(SANDBOX_ROOT, "notes/report.txt")
    response = client.post("/check", json={
        "tool": "read_file",
        "arguments": {"path": path}
    })
    data = response.json()
    assert data["action"] == "allow"
    assert "SAFE_REPORT" in data["result"]["content"]

def test_read_file_malicious_traversal():
    # Should be blocked
    path = os.path.join(SANDBOX_ROOT, "../../outside-3febd15a/canary.txt")
    response = client.post("/check", json={
        "tool": "read_file",
        "arguments": {"path": path}
    })
    data = response.json()
    assert data["action"] == "block"
    assert "Path traversal" in data["reason"]

def test_fetch_url_benign():
    # Should be allowed
    response = client.post("/check", json={
        "tool": "fetch_url",
        "arguments": {"url": "http://example.com"}
    })
    data = response.json()
    assert data["action"] == "allow"
    assert "Example Domain" in data["result"]["content"]

def test_fetch_url_malicious_localhost():
    # Should be blocked because it's not in ALLOWED_HOSTS
    response = client.post("/check", json={
        "tool": "fetch_url",
        "arguments": {"url": "http://127.0.0.1"}
    })
    data = response.json()
    assert data["action"] == "block"
    assert "not allowed" in data["reason"]

def test_fetch_url_malicious_userinfo():
    # Should be blocked
    response = client.post("/check", json={
        "tool": "fetch_url",
        "arguments": {"url": "http://example.com@127.0.0.1"}
    })
    data = response.json()
    assert data["action"] == "block"

if __name__ == "__main__":
    print("Run this file using: pytest test_guardrail.py -v")
