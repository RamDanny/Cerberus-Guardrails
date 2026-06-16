import re
import json
from pydantic import BaseModel, Field, ValidationError
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

# 1. Input WAF Layer Rules
JAILBREAK_PATTERNS = [
    re.compile(r'(ignore\s+all\s+previous\s+instructions)', re.IGNORECASE),
    re.compile(r'(system\s+prompt\s+leak|reveal\s+your\s+system\s+instructions)', re.IGNORECASE),
    re.compile(r'(you\s+are\s+now\s+in\s+dan\s+mode|do\s+anything\s+now)', re.IGNORECASE),
    re.compile(r'(override\s+developer\s+settings)', re.IGNORECASE)
]

def inspect_input_payload(body: dict) -> bool:
    '''
    Scans the Ollama prompt string for known adversarial manipulation vectors.
    '''
    prompt = body.get('prompt', '')
    if isinstance(prompt, str):
        for pattern in JAILBREAK_PATTERNS:
            if pattern.search(prompt):
                return False
    return True


# 2. Output Scrubbing Layer (PII Redaction)
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

def scrub_output_text(text: str) -> str:
    '''
    Scans the raw Ollama output string and replaces PII data with tokens.
    '''
    if not text.strip():
        return text
    results = analyzer.analyze(text=text, language='en', entities=['EMAIL_ADDRESS', 'PHONE_NUMBER', 'US_SSN'])
    anonymized_result = anonymizer.anonymize(text=text, analyzer_results=results)
    return anonymized_result.text


# 3. Tool-Gating / Execution Schema Verification Layer
class DatabaseQuerySchema(BaseModel):
    query: str = Field(..., description='SQL Query string extracted from model output.')
    
    def validate_safety(self) -> bool:
        forbidden_keywords = ['drop', 'delete', 'truncate', 'alter', ';']
        normalized_query = self.query.lower()
        if any(keyword in normalized_query for keyword in forbidden_keywords):
            return False
        return True

def verify_output_structural_safety(response_text: str) -> bool:
    '''
    If the model outputs structural JSON containing a database execution script,
    this function parses it and verifies safe compliance limits.
    '''
    # Clean standard markdown wrappers if the model wrapped its JSON output
    clean_text = response_text.replace('```json', '').replace('```', '').strip()
    
    # Check if the output string contains structural data trying to command a query
    if 'query' in clean_text and clean_text.startswith('{') and clean_text.endswith('}'):
        try:
            data = json.loads(clean_text)
            if 'query' in data:
                validated_query = DatabaseQuerySchema(query=data['query'])
                return validated_query.validate_safety()
        except (json.JSONDecodeError, ValidationError):
            return False  # Fail safe: Block malformed execution targets
            
    return True