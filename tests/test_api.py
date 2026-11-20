import pytest
from fastapi.testclient import TestClient
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.app import app

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_predict_safe_url():
    response = client.post("/predict", json={"url": "https://www.google.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["url"] == "https://www.google.com"
    assert data["status"] == "SAFE"
    assert data["action"] == "ALLOW"
    assert data["risk_score"] < 30

def test_predict_suspicious_url():
    # A URL with some suspicious features but maybe not fully phishing
    response = client.post("/predict", json={"url": "http://example.com/login-verify-account"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["SUSPICIOUS", "PHISHING", "MALICIOUS"]
    assert data["risk_score"] >= 30

def test_stats_endpoint():
    response = client.get("/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "safe" in data

def test_history_endpoint():
    response = client.get("/history?limit=5")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
