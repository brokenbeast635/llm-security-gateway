from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re
import time
import uvicorn

app = FastAPI(title="AI Security Gateway", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── PII Patterns ───────────────────────────────────────────────────────────
PII_PATTERNS = {
    "email":       r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "phone":       r'\b(\+92|0)?[0-9]{10,11}\b',
    "cnic":        r'\b\d{5}-\d{7}-\d{1}\b',
    "api_key":     r'\b(sk-|pk-|AIza|AKIA)[A-Za-z0-9_\-]{16,}\b',
    "credit_card": r'\b(?:\d{4}[- ]?){3}\d{4}\b',
    "ip_address":  r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    "name":        r'\b(Mr\.|Mrs\.|Dr\.|Miss\.?)\s+[A-Z][a-z]+\b',
}

# ─── Injection Patterns ──────────────────────────────────────────────────────
INJECTION_PATTERNS = [
    r'ignore\s+(all\s+)?(previous|prior|above)\s+instructions?',
    r'you\s+are\s+now\s+.*?(dan|jailbreak|evil|unrestricted)',
    r'(pretend|act|behave|roleplay)\s+(as|like)\s+(if\s+)?(you\s+(are|were|have\s+no))',
    r'(disregard|forget|bypass|override)\s+(your\s+)?(rules?|ethics?|guidelines?|constraints?|training)',
    r'do\s+anything\s+now',
    r'prompt\s+inject',
    r'system\s*:\s*(you\s+are|ignore)',
    r'(reveal|expose|show|leak)\s+(your\s+)?(system\s+prompt|instructions?)',
    r'jailbreak',
    r'grandmother\s+exploit',
    r'(token\s+smuggling|virtual\s+scenario)',
]

class AnalyzeRequest(BaseModel):
    text: str

def detect_injection(text: str) -> dict:
    text_lower = text.lower()
    matched = []
    score = 0
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text_lower):
            matched.append(pattern)
            score += 25
    score = min(score, 100)
    return {"score": score, "matched_patterns": matched, "is_injection": score >= 50}

def detect_pii(text: str) -> dict:
    found = {}
    masked_text = text
    for label, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            found[label] = matches
            for match in matches:
                m = match if isinstance(match, str) else match[0]
                masked_text = masked_text.replace(m, f"[{label.upper()}_REDACTED]")
    return {"pii_found": found, "masked_text": masked_text, "has_pii": len(found) > 0}

def policy_engine(injection_result: dict, pii_result: dict) -> dict:
    if injection_result["is_injection"]:
        return {"decision": "BLOCK", "reason": "Prompt injection detected", "color": "red"}
    if pii_result["has_pii"]:
        return {"decision": "MASK", "reason": "PII detected and masked", "color": "orange"}
    return {"decision": "ALLOW", "reason": "Input is safe", "color": "green"}

@app.get("/")
def root():
    return {"message": "AI Security Gateway is running!", "status": "active"}

@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    start = time.time()
    injection = detect_injection(req.text)
    pii = detect_pii(req.text)
    policy = policy_engine(injection, pii)
    latency = round((time.time() - start) * 1000, 2)
    return {
        "original_text": req.text,
        "injection_detection": injection,
        "pii_detection": pii,
        "policy": policy,
        "latency_ms": latency,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }

@app.get("/health")
def health():
    return {"status": "healthy", "version": "1.0.0"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)