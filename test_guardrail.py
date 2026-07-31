import pytest
from fastapi.testclient import TestClient
from app import app, SANDBOX_ROOT
import os

client = TestClient(app)

def test_read_file_benign():
    path = os.path.join(SANDBOX_ROOT, "notes/report.txt")
    response = client.post("/check", json={
        "tool": "read_file",
        "arguments": {"path": path}
    })
    data = response.json()
    assert data["action"] == "allow"
    assert "SAFE_REPORT" in data["result"]["content"]

def test_read_file_malicious_traversal():
    path = os.path.join(SANDBOX_ROOT, "../../outside-3febd15a/canary.txt")
    response = client.post("/check", json={
        "tool": "read_file",
        "arguments": {"path": path}
    })
    data = response.json()
    assert data["action"] == "block"

def test_read_file_double_encoding():
    # Double url encoding %252e%252e%252f
    path = "sandbox-50cef2fa8d/%252e%252e%252foutside-3febd15a/canary.txt"
    response = client.post("/check", json={
        "tool": "read_file",
        "arguments": {"path": path}
    })
    data = response.json()
    assert data["action"] == "block"

def test_read_file_backslash_traversal():
    # Backslashes on Linux
    path = "sandbox-50cef2fa8d/..\\..\\outside-3febd15a\\canary.txt"
    response = client.post("/check", json={
        "tool": "read_file",
        "arguments": {"path": path}
    })
    data = response.json()
    assert data["action"] == "block"

def test_fetch_url_benign():
    response = client.post("/check", json={
        "tool": "fetch_url",
        "arguments": {"url": "http://example.com"}
    })
    data = response.json()
    assert data["action"] == "allow"
    assert "Example Domain" in data["result"]["content"]

def test_fetch_url_userinfo():
    response = client.post("/check", json={
        "tool": "fetch_url",
        "arguments": {"url": "http://user:pass@example.com"}
    })
    data = response.json()
    assert data["action"] == "block"

def test_fetch_url_userinfo_at():
    response = client.post("/check", json={
        "tool": "fetch_url",
        "arguments": {"url": "http://example.com@example.com"}
    })
    data = response.json()
    assert data["action"] == "block"

if __name__ == "__main__":
    print("Run this file using: pytest test_guardrail.py -v")
