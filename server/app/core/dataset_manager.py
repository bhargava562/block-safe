"""
BlockSafe Scam Dataset Manager
Manages loading and updating of scam patterns dataset
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass
from difflib import SequenceMatcher

from app.utils.logger import logger


@dataclass
class ScamPattern:
    """Represents a scam pattern from the dataset"""
    scam_id: str
    category: str
    scam_type: str
    channels: List[str]
    description: str
    common_keywords: List[str]
    behavioral_patterns: List[str]
    risk_level: str


class ScamDatasetManager:
    """Manages scam dataset loading and updating"""
    
    def __init__(self, dataset_path: str = None):
        self.dataset_path = dataset_path or os.path.join(
            os.path.dirname(__file__), "..", "data", "scam_dataset.json"
        )
        self.dataset: Dict = {}
        self.patterns: List[ScamPattern] = []
        self.load_dataset()
    
    def load_dataset(self) -> None:
        """Load scam dataset from JSON file"""
        try:
            with open(self.dataset_path, 'r', encoding='utf-8') as f:
                self.dataset = json.load(f)
            
            # Convert to ScamPattern objects
            self.patterns = []
            for scam_data in self.dataset.get('scams', []):
                pattern = ScamPattern(
                    scam_id=scam_data['scam_id'],
                    category=scam_data['category'],
                    scam_type=scam_data['scam_type'],
                    channels=scam_data['channels'],
                    description=scam_data['description'],
                    common_keywords=scam_data['common_keywords'],
                    behavioral_patterns=scam_data['behavioral_patterns'],
                    risk_level=scam_data['risk_level']
                )
                self.patterns.append(pattern)
            
            logger.info(f"Loaded {len(self.patterns)} scam patterns from dataset")
            
        except FileNotFoundError:
            logger.error(f"Dataset file not found: {self.dataset_path}")
            self.dataset = {"scams": []}
            self.patterns = []
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in dataset: {e}")
            self.dataset = {"scams": []}
            self.patterns = []
    
    def find_similar_patterns(self, message: str, threshold: float = 0.7) -> List[ScamPattern]:
        """Find similar scam patterns based on keywords and behavioral patterns"""
        similar_patterns = []
        message_lower = message.lower()
        
        for pattern in self.patterns:
            similarity_score = 0
            matches = 0
            
            # Check keyword matches
            for keyword in pattern.common_keywords:
                if keyword.lower() in message_lower:
                    matches += 1
                    similarity_score += 0.3
            
            # Check behavioral pattern indicators
            for behavior in pattern.behavioral_patterns:
                if self._check_behavioral_match(message_lower, behavior):
                    matches += 1
                    similarity_score += 0.4
            
            # Normalize score
            total_indicators = len(pattern.common_keywords) + len(pattern.behavioral_patterns)
            if total_indicators > 0:
                normalized_score = similarity_score / total_indicators
                if normalized_score >= threshold:
                    similar_patterns.append(pattern)
        
        return similar_patterns
    
    def _check_behavioral_match(self, message: str, behavior: str) -> bool:
        """Check if message matches behavioral pattern"""
        behavior_indicators = {
            "creates urgency": ["urgent", "immediately", "now", "quick", "asap"],
            "asks for OTP": ["otp", "verification code", "6 digit", "code"],
            "asks for CVV or PIN": ["cvv", "pin", "card number", "16 digit"],
            "impersonates bank official": ["bank", "manager", "officer", "security"],
            "reverse payment logic": ["receive money", "get refund", "collect"],
            "fake refund story": ["refund", "cancelled", "return money"],
            "screenshare request": ["screen share", "anydesk", "teamviewer"],
            "asks for upfront fee": ["registration fee", "processing fee", "advance"],
            "too-good-to-be-true salary": ["lakh", "high salary", "easy money"],
            "fear intimidation": ["arrest", "legal action", "police", "court"],
            "asks for immediate payment": ["pay now", "transfer", "send money"],
            "voice cloning": ["emergency", "help me", "trust me"],
            "emotional manipulation": ["love", "relationship", "future"]
        }
        
        indicators = behavior_indicators.get(behavior.lower(), [])
        return any(indicator in message for indicator in indicators)
    
    def is_duplicate_pattern(self, new_scam_data: Dict, similarity_threshold: float = 0.8) -> bool:
        """Check if new scam pattern is too similar to existing ones"""
        new_keywords = set(kw.lower() for kw in new_scam_data.get('common_keywords', []))
        new_behaviors = set(bp.lower() for bp in new_scam_data.get('behavioral_patterns', []))
        
        for pattern in self.patterns:
            existing_keywords = set(kw.lower() for kw in pattern.common_keywords)
            existing_behaviors = set(bp.lower() for bp in pattern.behavioral_patterns)
            
            # Calculate similarity
            keyword_similarity = self._jaccard_similarity(new_keywords, existing_keywords)
            behavior_similarity = self._jaccard_similarity(new_behaviors, existing_behaviors)
            
            # Check if same category and type
            same_category = new_scam_data.get('category', '').lower() == pattern.category.lower()
            same_type = new_scam_data.get('scam_type', '').lower() == pattern.scam_type.lower()
            
            # If high similarity in both keywords and behaviors, consider duplicate
            if (keyword_similarity > similarity_threshold and 
                behavior_similarity > similarity_threshold and
                same_category):
                return True
        
        return False
    
    def _jaccard_similarity(self, set1: set, set2: set) -> float:
        """Calculate Jaccard similarity between two sets"""
        if not set1 and not set2:
            return 1.0
        if not set1 or not set2:
            return 0.0
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        return intersection / union if union > 0 else 0.0
    
    def add_new_pattern(self, scam_data: Dict) -> bool:
        """Add new scam pattern if it's not a duplicate"""
        if self.is_duplicate_pattern(scam_data):
            logger.info(f"Duplicate pattern detected, not adding: {scam_data.get('scam_type')}")
            return False
        
        # Generate new scam ID
        category_prefix = scam_data['category'].upper().replace(' ', '_')[:3]
        existing_ids = [p.scam_id for p in self.patterns if p.scam_id.startswith(f"SCAM_{category_prefix}")]
        next_id = len(existing_ids) + 1
        scam_data['scam_id'] = f"SCAM_{category_prefix}_{next_id:03d}"
        
        # Add to dataset
        self.dataset['scams'].append(scam_data)
        self.dataset['last_updated'] = datetime.now().strftime("%Y-%m-%d")
        
        # Create pattern object
        pattern = ScamPattern(
            scam_id=scam_data['scam_id'],
            category=scam_data['category'],
            scam_type=scam_data['scam_type'],
            channels=scam_data['channels'],
            description=scam_data['description'],
            common_keywords=scam_data['common_keywords'],
            behavioral_patterns=scam_data['behavioral_patterns'],
            risk_level=scam_data['risk_level']
        )
        self.patterns.append(pattern)
        
        # Save to file
        self.save_dataset()
        logger.info(f"Added new scam pattern: {scam_data['scam_id']} - {scam_data['scam_type']}")
        return True
    
    def save_dataset(self) -> None:
        """Save dataset to JSON file"""
        try:
            with open(self.dataset_path, 'w', encoding='utf-8') as f:
                json.dump(self.dataset, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save dataset: {e}")
    
    def get_pattern_by_type(self, scam_type: str) -> Optional[ScamPattern]:
        """Get pattern by scam type"""
        for pattern in self.patterns:
            if pattern.scam_type.lower() == scam_type.lower():
                return pattern
        return None
    
    def get_patterns_by_category(self, category: str) -> List[ScamPattern]:
        """Get all patterns in a category"""
        return [p for p in self.patterns if p.category.lower() == category.lower()]


# Singleton instance
_dataset_manager: Optional[ScamDatasetManager] = None


def get_dataset_manager() -> ScamDatasetManager:
    """Get singleton dataset manager instance"""
    global _dataset_manager
    if _dataset_manager is None:
        _dataset_manager = ScamDatasetManager()
    return _dataset_manager