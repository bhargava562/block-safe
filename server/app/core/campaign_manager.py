"""
BlockSafe Campaign Manager
"Merging Intervals" engine for threat campaign clustering.

Scam A (Existing):  SBI KYC Scam via SMS, Link: sbi-update.in
Scam B (New):       SBI PAN Scam via WhatsApp, Link: sbi-update.in, Phone: +91-999...
Merge Result:       Combined campaign tracking both SMS + WhatsApp, all indicators merged.

If overlap threshold is high (same link, phone, or UPI) → MERGE
If zero overlap (brand new Fedex scam) → CREATE new campaign
"""

import json
import os
import asyncio
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from app.utils.logger import logger


# ─────────────────────────────────────────────────────────────────────────────
# Campaign Result Dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CampaignProcessResult:
    """Result from campaign processing — returned to the API layer."""
    campaign_id: str
    is_new_campaign: bool
    total_attempts_tracked: int
    primary_target_entity: str


# ─────────────────────────────────────────────────────────────────────────────
# Campaign Manager
# ─────────────────────────────────────────────────────────────────────────────

class CampaignManager:
    """
    Manages the scam_campaigns.json file using "Merging Intervals" logic.

    When a new scam arrives, the manager:
    1. Loads existing campaigns
    2. Calculates similarity/overlap against each campaign
    3. If overlap found → MERGE (union arrays, update timestamps, increment counter)
    4. If no overlap → CREATE new campaign object
    5. Saves the updated dataset

    Thread-safe via asyncio.Lock.
    """

    def __init__(self, dataset_path: str = None):
        self.dataset_path = dataset_path or os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "data", "scam_campaigns.json"
        )
        self._lock = asyncio.Lock()
        self._campaigns: List[Dict[str, Any]] = []
        self._loaded = False

    def load_campaigns(self) -> List[Dict[str, Any]]:
        """Load campaigns from JSON file."""
        try:
            if os.path.exists(self.dataset_path):
                with open(self.dataset_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        self._campaigns = data
                    else:
                        self._campaigns = []
            else:
                self._campaigns = []
            self._loaded = True
            logger.info(f"CampaignManager: Loaded {len(self._campaigns)} campaigns")
        except Exception as e:
            logger.error(f"CampaignManager: Failed to load campaigns: {e}")
            self._campaigns = []
            self._loaded = True
        return self._campaigns

    def save_campaigns(self) -> None:
        """Save campaigns to JSON file (thread-safe write)."""
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.dataset_path), exist_ok=True)

            with open(self.dataset_path, "w", encoding="utf-8") as f:
                json.dump(self._campaigns, f, indent=2, ensure_ascii=False)

            logger.info(f"CampaignManager: Saved {len(self._campaigns)} campaigns")
        except Exception as e:
            logger.error(f"CampaignManager: Failed to save campaigns: {e}")

    async def process_scam(
        self,
        message: str,
        artifacts: Dict[str, Any],
        ai_feedback: Dict[str, Any],
        aggregated_score: float,
        claimed_entity: str,
        scam_category: str,
    ) -> Dict[str, Any]:
        """
        Main entry point: process a new scam through the merging engine.

        Returns dict with campaign_id, is_new_campaign, total_attempts_tracked,
        and primary_target_entity.
        """
        async with self._lock:
            if not self._loaded:
                self.load_campaigns()

            now = datetime.now(timezone.utc).isoformat()

            # Step 1: Find matching campaign
            match_idx = self._find_matching_campaign(
                artifacts=artifacts,
                claimed_entity=claimed_entity,
                scam_category=scam_category,
            )

            if match_idx is not None:
                # Step 2a: MERGE into existing campaign
                campaign = self._merge_into_campaign(
                    campaign_idx=match_idx,
                    message=message,
                    artifacts=artifacts,
                    ai_feedback=ai_feedback,
                    aggregated_score=aggregated_score,
                    timestamp=now,
                )
                is_new = False
                logger.info(
                    f"CampaignManager: Merged into {campaign['campaign_id']} "
                    f"(attempts: {campaign['total_attempts_tracked']})"
                )
            else:
                # Step 2b: CREATE new campaign
                campaign = self._create_new_campaign(
                    message=message,
                    artifacts=artifacts,
                    ai_feedback=ai_feedback,
                    aggregated_score=aggregated_score,
                    claimed_entity=claimed_entity,
                    scam_category=scam_category,
                    timestamp=now,
                )
                self._campaigns.append(campaign)
                is_new = True
                logger.info(f"CampaignManager: Created new {campaign['campaign_id']}")

            # Step 3: Save to disk
            self.save_campaigns()

            return {
                "campaign_id": campaign["campaign_id"],
                "is_new_campaign": is_new,
                "total_attempts_tracked": campaign["total_attempts_tracked"],
                "primary_target_entity": campaign["primary_target_entity"],
            }

    # ─────────────────────────────────────────────────────────────────────
    # Step 1: Find Matching Campaign (The "Interval Overlap" Check)
    # ─────────────────────────────────────────────────────────────────────

    def _find_matching_campaign(
        self,
        artifacts: Dict[str, Any],
        claimed_entity: str,
        scam_category: str,
    ) -> Optional[int]:
        """
        Scan existing campaigns for overlaps. Returns index of the best match,
        or None if no match found.

        Overlap criteria (in priority order):
        1. Same extracted_link domain → INSTANT MATCH
        2. Same extracted_phone → INSTANT MATCH
        3. Same extracted_upi → INSTANT MATCH
        4. Same entity + same category + partial artifact overlap → MATCH
        """
        new_links = set(artifacts.get("extracted_links", []))
        new_domains = set(artifacts.get("extracted_domains", []))
        new_phones = set(artifacts.get("extracted_phones", []))
        new_upis = set(artifacts.get("extracted_upis", []))
        new_entity = _normalize_entity(claimed_entity)

        best_match_idx = None
        best_overlap_score = 0.0

        for idx, campaign in enumerate(self._campaigns):
            threat = campaign.get("threat_artifacts", {})
            camp_links = set(threat.get("extracted_links", []))
            camp_phones = set(threat.get("extracted_phones", []))
            camp_upis = set(threat.get("extracted_upis", []))
            camp_entity = _normalize_entity(
                campaign.get("primary_target_entity", "")
            )

            # Extract domains from campaign links for domain-level matching
            camp_domains = set()
            for link in camp_links:
                domain_match = re.search(
                    r'(?:https?://)?(?:www\.)?([^/\s]+)', link
                )
                if domain_match:
                    camp_domains.add(domain_match.group(1).lower())

            overlap_score = 0.0

            # Priority 1: Link/domain overlap (instant match)
            link_overlap = new_links & camp_links
            domain_overlap = new_domains & camp_domains
            if link_overlap or domain_overlap:
                overlap_score += 1.0

            # Priority 2: Phone overlap (instant match)
            phone_overlap = new_phones & camp_phones
            if phone_overlap:
                overlap_score += 1.0

            # Priority 3: UPI overlap (instant match)
            upi_overlap = new_upis & camp_upis
            if upi_overlap:
                overlap_score += 1.0

            # Priority 4: Entity + category match (weaker signal)
            if new_entity and camp_entity and new_entity == camp_entity:
                overlap_score += 0.4
                camp_category = campaign.get("scam_category", "").lower()
                if scam_category and scam_category.lower() == camp_category:
                    overlap_score += 0.2

            if overlap_score > best_overlap_score:
                best_overlap_score = overlap_score
                best_match_idx = idx

        # Return match only if overlap is significant enough
        if best_overlap_score >= 0.6:
            return best_match_idx

        return None

    # ─────────────────────────────────────────────────────────────────────
    # Step 2a: The Merge Action
    # ─────────────────────────────────────────────────────────────────────

    def _merge_into_campaign(
        self,
        campaign_idx: int,
        message: str,
        artifacts: Dict[str, Any],
        ai_feedback: Dict[str, Any],
        aggregated_score: float,
        timestamp: str,
    ) -> Dict[str, Any]:
        """
        Merge new scam data into an existing campaign.

        Like [1,5] + [4,8] → [1,8]:
        - Union-merge all artifact arrays (set dedup)
        - Append raw message variant
        - Update last_seen timestamp
        - Increment total_attempts_tracked
        - Running weighted average of aggregated_scam_score
        - Refresh ai_feedback with latest analysis
        """
        campaign = self._campaigns[campaign_idx]
        threat = campaign.setdefault("threat_artifacts", {})

        # Union-merge channels
        existing_channels = set(threat.get("channels_used", []))
        new_channels = set(artifacts.get("channels_detected", []))
        threat["channels_used"] = sorted(existing_channels | new_channels)

        # Union-merge links
        existing_links = set(threat.get("extracted_links", []))
        new_links = set(artifacts.get("extracted_links", []))
        threat["extracted_links"] = sorted(existing_links | new_links)

        # Union-merge phones
        existing_phones = set(threat.get("extracted_phones", []))
        new_phones = set(artifacts.get("extracted_phones", []))
        threat["extracted_phones"] = sorted(existing_phones | new_phones)

        # Union-merge UPIs
        existing_upis = set(threat.get("extracted_upis", []))
        new_upis = set(artifacts.get("extracted_upis", []))
        threat["extracted_upis"] = sorted(existing_upis | new_upis)

        # Append raw message variant (deduped)
        variants = campaign.setdefault("raw_message_variants", [])
        trimmed = message.strip()[:500]  # Cap message length
        if trimmed not in variants:
            variants.append(trimmed)

        # Update timestamps
        campaign["last_seen"] = timestamp

        # Increment attempt counter
        campaign["total_attempts_tracked"] = (
            campaign.get("total_attempts_tracked", 1) + 1
        )

        # Running weighted average of score
        old_score = campaign.get("aggregated_scam_score", 0.5)
        old_count = campaign.get("total_attempts_tracked", 2) - 1
        campaign["aggregated_scam_score"] = round(
            (old_score * old_count + aggregated_score) / (old_count + 1), 4
        )

        # Refresh AI feedback with latest analysis
        campaign["ai_feedback"] = {
            "openai_emotional_profile": ai_feedback.get(
                "openai_emotional_profile",
                campaign.get("ai_feedback", {}).get("openai_emotional_profile", "")
            ),
            "gemini_policy_violations": ai_feedback.get(
                "gemini_policy_violations",
                campaign.get("ai_feedback", {}).get("gemini_policy_violations", "")
            ),
            "primary_suspected_reason": ai_feedback.get(
                "primary_suspected_reason",
                campaign.get("ai_feedback", {}).get("primary_suspected_reason", "")
            ),
        }

        self._campaigns[campaign_idx] = campaign
        return campaign

    # ─────────────────────────────────────────────────────────────────────
    # Step 2b: Create New Campaign
    # ─────────────────────────────────────────────────────────────────────

    def _create_new_campaign(
        self,
        message: str,
        artifacts: Dict[str, Any],
        ai_feedback: Dict[str, Any],
        aggregated_score: float,
        claimed_entity: str,
        scam_category: str,
        timestamp: str,
    ) -> Dict[str, Any]:
        """Create a brand new campaign object."""
        campaign_id = self._generate_campaign_id(claimed_entity, scam_category)

        return {
            "campaign_id": campaign_id,
            "primary_target_entity": claimed_entity or "Unknown",
            "scam_category": scam_category or "Unknown",
            "aggregated_scam_score": round(aggregated_score, 4),
            "total_attempts_tracked": 1,
            "first_seen": timestamp,
            "last_seen": timestamp,
            "threat_artifacts": {
                "channels_used": artifacts.get("channels_detected", ["SMS"]),
                "extracted_links": artifacts.get("extracted_links", []),
                "extracted_phones": artifacts.get("extracted_phones", []),
                "extracted_upis": artifacts.get("extracted_upis", []),
            },
            "ai_feedback": {
                "openai_emotional_profile": ai_feedback.get(
                    "openai_emotional_profile", ""
                ),
                "gemini_policy_violations": ai_feedback.get(
                    "gemini_policy_violations", ""
                ),
                "primary_suspected_reason": ai_feedback.get(
                    "primary_suspected_reason", ""
                ),
            },
            "raw_message_variants": [message.strip()[:500]],
        }

    # ─────────────────────────────────────────────────────────────────────
    # Campaign ID Generator
    # ─────────────────────────────────────────────────────────────────────

    def _generate_campaign_id(
        self, entity: str, category: str
    ) -> str:
        """
        Generate IDs like CAMP-SBI-KYC-001, CAMP-AMAZON-REFUND-002, etc.
        """
        # Normalize entity to short code
        entity_code = _normalize_entity(entity).upper()[:10] or "UNK"
        entity_code = re.sub(r'[^A-Z0-9]', '', entity_code)

        # Normalize category to short code
        cat_code = category.upper()[:10] if category else "MISC"
        cat_code = re.sub(r'[^A-Z0-9]', '', cat_code)

        # Find next sequence number for this entity
        existing_count = sum(
            1 for c in self._campaigns
            if _normalize_entity(
                c.get("primary_target_entity", "")
            ).upper()[:10] == entity_code
        )

        seq = str(existing_count + 1).zfill(3)
        return f"CAMP-{entity_code}-{cat_code}-{seq}"

    # ─────────────────────────────────────────────────────────────────────
    # Public Accessors
    # ─────────────────────────────────────────────────────────────────────

    def get_all_campaigns(self) -> List[Dict[str, Any]]:
        """Return all campaigns (for the /campaigns API endpoint)."""
        if not self._loaded:
            self.load_campaigns()
        return self._campaigns

    def get_campaign_stats(self) -> Dict[str, Any]:
        """Return campaign statistics."""
        if not self._loaded:
            self.load_campaigns()

        total = len(self._campaigns)
        total_attempts = sum(
            c.get("total_attempts_tracked", 0) for c in self._campaigns
        )

        entities = {}
        categories = {}
        for c in self._campaigns:
            ent = c.get("primary_target_entity", "Unknown")
            cat = c.get("scam_category", "Unknown")
            entities[ent] = entities.get(ent, 0) + 1
            categories[cat] = categories.get(cat, 0) + 1

        return {
            "total_campaigns": total,
            "total_scam_attempts_tracked": total_attempts,
            "entities_targeted": entities,
            "categories": categories,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_entity(name: str) -> str:
    """Normalize entity name for comparison."""
    if not name:
        return ""

    name = name.lower().strip()

    # Common abbreviation normalization
    replacements = {
        "state bank of india": "sbi",
        "reserve bank of india": "rbi",
        "central bureau of investigation": "cbi",
        "income tax department": "incometax",
        "amazon india": "amazon",
        "flipkart india": "flipkart",
    }

    for full, short in replacements.items():
        if full in name:
            return short

    # Remove common suffixes
    for suffix in ["bank", "ltd", "limited", "inc", "pvt", "private"]:
        name = name.replace(suffix, "").strip()

    return re.sub(r'\s+', '', name)


# ─────────────────────────────────────────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────────────────────────────────────────

_campaign_manager: Optional[CampaignManager] = None


def get_campaign_manager() -> CampaignManager:
    """Get singleton CampaignManager instance."""
    global _campaign_manager
    if _campaign_manager is None:
        _campaign_manager = CampaignManager()
    return _campaign_manager
