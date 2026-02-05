"""
BlockSafe Dataset Updater
Automatically updates scam dataset when new patterns are detected
"""

import asyncio
from typing import Dict, List, Optional
from datetime import datetime

from google import genai
from google.genai import types

from app.config import get_settings
from app.core.dataset_manager import get_dataset_manager, ScamPattern
from app.core.scam_detector import ClassificationResult
from app.core.ssf_engine import SSFResult
from app.utils.logger import logger


class DatasetUpdater:
    """Automatically updates scam dataset with new patterns"""
    
    def __init__(self):
        self.dataset_manager = get_dataset_manager()
        self.settings = get_settings()
        self._client = None
        self._configure_ai()
    
    def _configure_ai(self):
        """Configure AI client for pattern analysis"""
        try:
            self._client = genai.Client(
                api_key=self.settings.GEMINI_API_KEY.get_secret_value()
            )
        except Exception as e:
            logger.error(f"Failed to configure AI for dataset updater: {e}")
    
    async def analyze_for_new_pattern(
        self, 
        message: str, 
        classification: ClassificationResult,
        ssf_result: SSFResult
    ) -> bool:
        """
        Analyze if detected scam represents a new pattern worth adding to dataset
        
        Args:
            message: The scam message
            classification: AI classification result
            ssf_result: Scam strategy fingerprint
            
        Returns:
            True if new pattern was added, False otherwise
        """
        if not classification.is_scam or classification.confidence < 0.8:
            return False
        
        # Check if similar patterns already exist
        similar_patterns = self.dataset_manager.find_similar_patterns(message, threshold=0.6)
        
        if len(similar_patterns) >= 2:
            # Too many similar patterns, likely not new
            logger.debug("Similar patterns found, not adding to dataset")
            return False
        
        # Use AI to analyze if this is a genuinely new pattern
        is_new_pattern = await self._ai_analyze_novelty(message, classification, similar_patterns)
        
        if not is_new_pattern:
            return False
        
        # Generate new pattern data
        new_pattern_data = await self._generate_pattern_data(message, classification, ssf_result)
        
        if new_pattern_data:
            return self.dataset_manager.add_new_pattern(new_pattern_data)
        
        return False
    
    async def _ai_analyze_novelty(
        self, 
        message: str, 
        classification: ClassificationResult,
        similar_patterns: List[ScamPattern]
    ) -> bool:
        """Use AI to determine if this is a genuinely new scam pattern"""
        if not self._client:
            return False
        
        similar_descriptions = [p.description for p in similar_patterns[:3]]
        
        prompt = f"""Analyze if this scam message represents a NEW scam pattern or variation.

MESSAGE: {message}
DETECTED TYPE: {classification.scam_type}
CONFIDENCE: {classification.confidence}

EXISTING SIMILAR PATTERNS:
{chr(10).join(f"- {desc}" for desc in similar_descriptions)}

Determine if this message shows:
1. A completely new scam technique/approach
2. A significant variation of existing patterns
3. Just another instance of known patterns

Respond with JSON:
{{
    "is_new_pattern": true/false,
    "novelty_score": 0.0-1.0,
    "reasoning": "explanation"
}}"""

        try:
            response = await self._client.aio.models.generate_content(
                model=self.settings.GEMINI_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.2,
                    max_output_tokens=512
                )
            )
            
            import json
            result = json.loads(response.text.strip())
            
            is_new = result.get('is_new_pattern', False)
            novelty_score = result.get('novelty_score', 0.0)
            
            logger.info(f"Novelty analysis: new={is_new}, score={novelty_score}")
            
            return is_new and novelty_score >= 0.7
            
        except Exception as e:
            logger.error(f"AI novelty analysis failed: {e}")
            return False
    
    async def _generate_pattern_data(
        self, 
        message: str, 
        classification: ClassificationResult,
        ssf_result: SSFResult
    ) -> Optional[Dict]:
        """Generate new pattern data using AI analysis"""
        if not self._client:
            return None
        
        prompt = f"""Analyze this scam message and generate a comprehensive pattern definition.

MESSAGE: {message}
SCAM TYPE: {classification.scam_type}
CONFIDENCE: {classification.confidence}
URGENCY SCORE: {ssf_result.urgency_score}
AUTHORITY CLAIMS: {ssf_result.authority_claims}
URGENCY PHRASES: {ssf_result.urgency_phrases}

Generate a complete scam pattern in JSON format:
{{
    "category": "Banking & Finance" | "Digital Payments" | "Job & Employment" | "Romance & Social Engineering" | "Tech Support" | "Crypto & Investment" | "Government & Authority" | "E-Commerce" | "AI & Deepfake" | "Other",
    "scam_type": "descriptive name for this scam type",
    "channels": ["call", "sms", "whatsapp", "email", "etc"],
    "description": "clear description of how this scam works",
    "common_keywords": ["list", "of", "keywords", "found", "in", "this", "type"],
    "behavioral_patterns": ["list", "of", "behavioral", "indicators"],
    "risk_level": "low" | "medium" | "high" | "critical"
}}

Extract actual keywords and patterns from the message. Be specific and accurate."""

        try:
            response = await self._client.aio.models.generate_content(
                model=self.settings.GEMINI_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.3,
                    max_output_tokens=1024
                )
            )
            
            import json
            pattern_data = json.loads(response.text.strip())
            
            # Validate required fields
            required_fields = ['category', 'scam_type', 'channels', 'description', 
                             'common_keywords', 'behavioral_patterns', 'risk_level']
            
            if all(field in pattern_data for field in required_fields):
                logger.info(f"Generated new pattern: {pattern_data['scam_type']}")
                return pattern_data
            else:
                logger.error("Generated pattern missing required fields")
                return None
                
        except Exception as e:
            logger.error(f"Pattern generation failed: {e}")
            return None
    
    def get_dataset_stats(self) -> Dict:
        """Get current dataset statistics"""
        patterns = self.dataset_manager.patterns
        
        stats = {
            "total_patterns": len(patterns),
            "categories": {},
            "risk_levels": {},
            "last_updated": self.dataset_manager.dataset.get('last_updated', 'unknown')
        }
        
        for pattern in patterns:
            # Count by category
            stats["categories"][pattern.category] = stats["categories"].get(pattern.category, 0) + 1
            
            # Count by risk level
            stats["risk_levels"][pattern.risk_level] = stats["risk_levels"].get(pattern.risk_level, 0) + 1
        
        return stats


# Singleton instance
_dataset_updater: Optional[DatasetUpdater] = None


def get_dataset_updater() -> DatasetUpdater:
    """Get singleton dataset updater instance"""
    global _dataset_updater
    if _dataset_updater is None:
        _dataset_updater = DatasetUpdater()
    return _dataset_updater