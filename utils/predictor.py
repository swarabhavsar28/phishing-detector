"""Cached local model inference and transparent URL/text heuristics."""

from __future__ import annotations

import logging
import os
import re
import threading
from pathlib import Path
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

PHISHING_KEYWORDS = (
    "verify", "password", "bank", "account", "login",
    "urgent", "immediately", "suspend", "security", "alert",
)
SCAM_WORDS = ("won", "gift", "prize", "lottery", "claim", "free", "offer")
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

_MODEL_LOCK = threading.Lock()
_MODEL_PATH: Path | None = None
_TOKENIZER = None
_MODEL = None
_MODEL_ERROR = False


def _resolve_model_path(model_path: str | os.PathLike | None = None) -> Path:
    path = Path(model_path or os.environ.get("PHISHING_MODEL_PATH", "model/hf_model"))
    if not path.is_absolute():
        path = Path(__file__).resolve().parents[1] / path
    return path.resolve()


def _model_files_exist(path: Path) -> bool:
    return (path / "config.json").is_file() and any(
        (path / filename).is_file()
        for filename in ("model.safetensors", "pytorch_model.bin", "tf_model.h5")
    )


def model_status(model_path: str | os.PathLike | None = None) -> dict[str, str | bool]:
    """Report local model availability without loading weights."""
    path = _resolve_model_path(model_path)
    if not _model_files_exist(path):
        return {"state": "missing", "available": False, "loaded": False}
    with _MODEL_LOCK:
        if _MODEL_PATH == path and _MODEL is not None:
            return {"state": "loaded", "available": True, "loaded": True}
        if _MODEL_PATH == path and _MODEL_ERROR:
            return {"state": "load_error", "available": False, "loaded": False}
    return {"state": "available", "available": True, "loaded": False}


def _load_model(model_path: str | os.PathLike | None = None):
    global _MODEL_PATH, _TOKENIZER, _MODEL, _MODEL_ERROR
    path = _resolve_model_path(model_path)
    with _MODEL_LOCK:
        if _MODEL_PATH == path and (_MODEL is not None or _MODEL_ERROR):
            return _TOKENIZER, _MODEL

        _MODEL_PATH, _TOKENIZER, _MODEL, _MODEL_ERROR = path, None, None, False
        if not _model_files_exist(path):
            return None, None

        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            tokenizer = AutoTokenizer.from_pretrained(str(path), local_files_only=True)
            model = AutoModelForSequenceClassification.from_pretrained(
                str(path), local_files_only=True
            )
            model.eval()
            _TOKENIZER, _MODEL = tokenizer, model
        except Exception as exc:  # Keep the web app available in heuristic-only mode.
            _MODEL_ERROR = True
            logger.warning("Local model load failed (%s)", type(exc).__name__)
        return _TOKENIZER, _MODEL


def extract_urls(text: str) -> list[str]:
    """Extract literal HTTP(S) links without making a network request."""
    return [url.rstrip(".,;:!?)]}") for url in URL_PATTERN.findall(text)]


def _url_observations(url: str) -> tuple[int, list[str]]:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    score = 0
    observations: list[str] = []

    if parsed.scheme.lower() == "http":
        score += 25
        observations.append("The link uses HTTP rather than HTTPS.")
    matched_host_terms = [term for term in ("login", "verify", "bank") if term in host]
    if matched_host_terms:
        score += 30
        observations.append(
            "The hostname contains: " + ", ".join(matched_host_terms) + "."
        )
    if "-" in host:
        score += 20
        observations.append("The hostname contains a hyphen.")
    if host.count(".") > 2:
        score += 20
        observations.append("The hostname has more than two dots.")
    return score, observations


def analyze_text(text: str, model_path: str | os.PathLike | None = None) -> dict:
    """Analyze submitted content with the local classifier when available.

    Model class 1 is treated as the positive risk class, matching the original
    application's scoring convention. Heuristics remain explicitly available
    when local weights cannot be loaded.
    """
    text_lower = text.lower()
    phishing_hits = [word for word in PHISHING_KEYWORDS if word in text_lower]
    scam_hits = [word for word in SCAM_WORDS if word in text_lower]
    urls = extract_urls(text)

    keyword_points = len(phishing_hits) * 10
    scam_points = len(scam_hits) * 15
    url_points = 0
    observations: list[str] = []
    for url in urls:
        points, found = _url_observations(url)
        url_points += points
        observations.extend(found)
    for word in phishing_hits:
        observations.append(f"Message contains the indicator word ‘{word}’.")
    for word in scam_hits:
        observations.append(f"Message contains the offer-related word ‘{word}’.")

    tokenizer, model = _load_model(model_path)
    class1_score = None
    predicted_class = None
    if tokenizer is not None and model is not None:
        try:
            import torch

            model_inputs = tokenizer(
                text, return_tensors="pt", truncation=True, padding=True, max_length=256
            )
            with torch.inference_mode():
                logits = model(**model_inputs).logits
                probabilities = torch.softmax(logits, dim=1)[0]
            predicted_class = int(torch.argmax(probabilities).item())
            class1_score = float(probabilities[1].item())
        except Exception as exc:
            logger.warning("Local model inference failed (%s)", type(exc).__name__)

    model_component = class1_score * 100 * 0.6 if class1_score is not None else 0
    risk_score = round(min(100, model_component + keyword_points + scam_points + url_points), 2)
    if risk_score >= 70:
        label, classification = "HIGH RISK (Phishing)", "phishing"
    elif risk_score >= 40:
        label, classification = "MEDIUM RISK · REVIEW", "review"
    else:
        label, classification = "LOW RISK (Safe)", "legitimate"

    status = model_status(model_path)
    return {
        "label": label,
        "classification": classification,
        "risk_score": risk_score,
        "class1_score": round(class1_score * 100, 2) if class1_score is not None else None,
        "predicted_class": predicted_class,
        "model_state": status["state"] if class1_score is not None else (
            "inference_error" if status["available"] else status["state"]
        ),
        "model_used": class1_score is not None,
        "keywords": phishing_hits + scam_hits,
        "phishing_keywords": phishing_hits,
        "scam_words": scam_hits,
        "urls": urls,
        "observations": list(dict.fromkeys(observations)),
        "score_components": {
            "model": round(model_component, 2),
            "keywords": keyword_points,
            "offers": scam_points,
            "url_rules": url_points,
        },
    }


def predict_email(text: str) -> dict:
    """Backward-compatible entry point used by the original evaluation script."""
    return analyze_text(text)
