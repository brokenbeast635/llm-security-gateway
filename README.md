# LLM Security Gateway

AI (CSC 262) Lab Mid — Secure Gateway Design for LLM Applications

## Setup

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_lg
uvicorn main:app --reload --port 8000
```

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /analyze | Analyze input for injection + PII |
| GET | /thresholds | View current policy thresholds |
| PUT | /thresholds | Update policy thresholds |
| GET | /health | Health check |

## Pipeline
```
User Input → Injection Detection → PII Analyzer → Policy Decision → Output
```

## Evaluation

Run the test suite:
```bash
python test_gateway.py
```
