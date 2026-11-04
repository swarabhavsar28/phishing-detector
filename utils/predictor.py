from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import re
from urllib.parse import urlparse

model_path = "model/hf_model"

tokenizer = AutoTokenizer.from_pretrained(model_path)
model = AutoModelForSequenceClassification.from_pretrained(model_path)

# 🔥 phishing indicators
PHISHING_KEYWORDS = [
    "verify", "password", "bank", "account", "login",
    "urgent", "immediately", "suspend", "security", "alert"
]

SCAM_WORDS = [
    "won", "gift", "prize", "lottery", "claim", "free", "offer"
]

def extract_urls(text):
    return re.findall(r'(https?://\S+)', text)

def url_risk(url):
    score = 0
    domain = urlparse(url).netloc.lower()

    if url.startswith("http://"):
        score += 25

    if any(k in domain for k in ["login", "verify", "bank"]):
        score += 30

    if "-" in domain or domain.count('.') > 2:
        score += 20

    return score


def predict_email(text):
    text_lower = text.lower()

    # ===== AI MODEL =====
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True)
    outputs = model(**inputs)

    probs = torch.softmax(outputs.logits, dim=1)
    pred = torch.argmax(probs).item()
    confidence = probs[0][pred].item()

    ai_score = confidence * 100 if pred == 1 else (1 - confidence) * 100

    # ===== KEYWORD ANALYSIS =====
    keyword_hits = [w for w in PHISHING_KEYWORDS if w in text_lower]
    scam_hits = [w for w in SCAM_WORDS if w in text_lower]

    keyword_score = len(keyword_hits) * 10
    scam_score = len(scam_hits) * 15

    # ===== URL ANALYSIS =====
    urls = extract_urls(text)
    url_score = sum(url_risk(u) for u in urls)

    # ===== FINAL SCORE =====
    total_score = min(100, ai_score * 0.6 + keyword_score + scam_score + url_score)

    # ===== LABEL =====
    if total_score >= 70:
        label = "HIGH RISK (Phishing)"
    elif total_score >= 40:
        label = "MEDIUM RISK"
    else:
        label = "LOW RISK (Safe)"

    return {
        "label": label,
        "risk_score": round(total_score, 2),
        "keywords": keyword_hits + scam_hits,
        "urls": urls
    }