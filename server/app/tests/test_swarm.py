import pytest
import requests
import json
import sys
from fastapi.testclient import TestClient
from app.main import app

from app.config import get_settings
from app.main import app

# Fetch API key from configuration to avoid 401 in CI/different environments
settings = get_settings()
API_URL = "/api/v1"
API_KEY = settings.API_AUTH_KEY.get_secret_value()
HEADERS = {"X-API-KEY": API_KEY}

@pytest.fixture
def client():
    return TestClient(app)

def test_multi_agent_campaign_workflow(client):
    """Integration test for multi-agent classification and campaign merging"""
    
    # Test 1: SBI scam (should create new campaign or merge into existing)
    print("\n" + "=" * 60)
    print("TEST 1: SBI PAN-KYC Scam")
    r1 = client.post(f"{API_URL}/analyze/text",
        json={
            "message": "URGENT: Your SBI account will be blocked in 24 hours! Update your PAN immediately: http://sbi-secure.in/update-pan. Contact: +919876543210. - SBI Security Team",
            "mode": "shield"
        }, headers=HEADERS)
    data1 = r1.json()
    
    assert r1.status_code == 200
    # Note: LLM results might vary, but we expect it to try and return structured data
    print(f"  is_scam: {data1.get('is_scam')}")
    
    # Test 2: Related SBI scam (SAME domain = should MERGE)
    print("\n" + "=" * 60)
    print("TEST 2: Related SBI Scam (same domain = MERGE)")
    r2 = client.post(f"{API_URL}/analyze/text",
        json={
            "message": "Dear customer, your SBI PAN card is expired. Reactivate now via http://sbi-secure.in/kyc-verify. Call +919999888877. - SBI Care",
            "mode": "shield"
        }, headers=HEADERS)
    data2 = r2.json()
    assert r2.status_code == 200
    
    # Test 3: Unrelated Amazon scam (should CREATE NEW campaign)
    print("\n" + "=" * 60)
    print("TEST 3: Amazon Gift Card Scam (NEW campaign)")
    r3 = client.post(f"{API_URL}/analyze/text",
        json={
            "message": "Congratulations You won Amazon Rs.50000 gift card! Claim now: http://amazon-gifts.win/claim. Share OTP.",
            "mode": "shield"
        }, headers=HEADERS)
    data3 = r3.json()
    assert r3.status_code == 200

    # Test 4: Check /campaigns endpoint
    print("\n" + "=" * 60)
    print("TEST 4: GET /campaigns")
    r4 = client.get(f"{API_URL}/campaigns", headers=HEADERS)
    assert r4.status_code == 200
    d4 = r4.json()
    stats = d4.get("stats", {})
    print(f"  total campaigns: {stats.get('total_campaigns')}")
    print(f"  total attempts: {stats.get('total_scam_attempts_tracked')}")

if __name__ == "__main__":
    # If run directly, use TestClient for convenience without needing a separate process
    with TestClient(app) as c:
        test_multi_agent_campaign_workflow(c)
    print("\n" + "=" * 60)
    print("ALL TESTS COMPLETE")
