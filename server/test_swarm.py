"""Integration test: Multi-Agent Swarm + Merging Intervals"""
import requests
import json
import sys

API_URL = "http://localhost:8000/api/v1"
API_KEY = "D5N+u7NBbsYSPUkvWuVvpnUdIppxU2MtOwX2WmNzHZk="
HEADERS = {"X-API-KEY": API_KEY}

def analyze(msg):
    r = requests.post(f"{API_URL}/analyze/text",
        json={"message": msg, "mode": "shield"}, headers=HEADERS)
    return r.json()

# Test 1: SBI scam (should create new campaign or merge into existing)
print("=" * 60)
print("TEST 1: SBI PAN-KYC Scam")
data1 = analyze(
    "URGENT: Your SBI account will be blocked in 24 hours! "
    "Update your PAN immediately: http://sbi-secure.in/update-pan. "
    "Contact: +919876543210. - SBI Security Team"
)
print(f"  is_scam: {data1['is_scam']}")
print(f"  confidence: {data1['confidence']}")
af1 = data1.get("ai_feedback") or {}
print(f"  emotional: {af1.get('openai_emotional_profile', 'N/A')[:120]}")
print(f"  policy: {af1.get('gemini_policy_violations', 'N/A')[:120]}")
ci1 = data1.get("campaign_info") or {}
print(f"  campaign_id: {ci1.get('campaign_id', 'N/A')}")
print(f"  is_new: {ci1.get('is_new_campaign', 'N/A')}")
print(f"  attempts: {ci1.get('total_attempts_tracked', 'N/A')}")

# Test 2: Related SBI scam (SAME domain = should MERGE)
print("\n" + "=" * 60)
print("TEST 2: Related SBI Scam (same domain = MERGE)")
data2 = analyze(
    "Dear customer, your SBI PAN card is expired. Reactivate now "
    "via http://sbi-secure.in/kyc-verify. Call +919999888877. - SBI Care"
)
ci2 = data2.get("campaign_info") or {}
print(f"  campaign_id: {ci2.get('campaign_id', 'N/A')}")
print(f"  is_new: {ci2.get('is_new_campaign', 'N/A')}")
print(f"  attempts: {ci2.get('total_attempts_tracked', 'N/A')}")

# Test 3: Unrelated Amazon scam (should CREATE NEW campaign)
print("\n" + "=" * 60)
print("TEST 3: Amazon Gift Card Scam (NEW campaign)")
data3 = analyze(
    "Congratulations You won Amazon Rs.50000 gift card! "
    "Claim now: http://amazon-gifts.win/claim. Share OTP."
)
ci3 = data3.get("campaign_info") or {}
print(f"  campaign_id: {ci3.get('campaign_id', 'N/A')}")
print(f"  is_new: {ci3.get('is_new_campaign', 'N/A')}")
print(f"  attempts: {ci3.get('total_attempts_tracked', 'N/A')}")

# Test 4: Check /campaigns endpoint
print("\n" + "=" * 60)
print("TEST 4: GET /campaigns")
r4 = requests.get(f"{API_URL}/campaigns", headers=HEADERS)
d4 = r4.json()
stats = d4.get("stats", {})
print(f"  total campaigns: {stats.get('total_campaigns')}")
print(f"  total attempts: {stats.get('total_scam_attempts_tracked')}")
for c in d4.get("campaigns", []):
    cid = c.get("campaign_id", "?")
    ent = c.get("primary_target_entity", "?")
    att = c.get("total_attempts_tracked", 0)
    chans = c.get("threat_artifacts", {}).get("channels_used", [])
    links = c.get("threat_artifacts", {}).get("extracted_links", [])
    phones = c.get("threat_artifacts", {}).get("extracted_phones", [])
    print(f"  -> {cid}: {ent} | {att} attempts | channels={chans} links={links} phones={phones}")

print("\n" + "=" * 60)
print("ALL TESTS COMPLETE")
