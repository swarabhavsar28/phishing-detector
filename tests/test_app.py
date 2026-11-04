from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as application
from utils.predictor import analyze_text


def example_result(text: str, model_path=None) -> dict:
    suspicious = "login" in text.lower() or text.lower().startswith("http://")
    classification = "phishing" if suspicious else "legitimate"
    label = "HIGH RISK (Phishing)" if suspicious else "LOW RISK (Safe)"
    return {
        "label": label,
        "classification": classification,
        "risk_score": 82.5 if suspicious else 8.0,
        "class1_score": 71.4,
        "predicted_class": 1 if suspicious else 0,
        "model_state": "loaded",
        "model_used": True,
        "keywords": ["login"] if suspicious else [],
        "phishing_keywords": ["login"] if suspicious else [],
        "scam_words": [],
        "urls": [text],
        "observations": ["Hostname contains login."] if suspicious else [],
        "score_components": {"model": 42.8, "keywords": 10, "offers": 0, "url_rules": 30},
    }


class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.database = root / "history.sqlite3"
        self.model_path = root / "missing-model"
        self.app = application.create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-secret",
                "DATABASE": str(self.database),
                "MODEL_PATH": str(self.model_path),
            }
        )
        self.client = self.app.test_client()
        with self.client.session_transaction() as session:
            session["csrf_token"] = "test-csrf"
        self.csrf = {"csrf_token": "test-csrf"}

    def tearDown(self):
        self.temporary.cleanup()

    def query_database(self, query: str):
        connection = sqlite3.connect(self.database)
        try:
            return connection.execute(query).fetchall()
        finally:
            connection.close()

    def test_dashboard_uses_empty_database_counts(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"0</div>", response.data)
        self.assertIn(b"No scan data yet", response.data)
        self.assertIn(b"HEURISTICS ONLY", response.data)

    def test_url_scan_persists_sanitized_history_and_survives_app_restart(self):
        with patch("app.analyze_text", side_effect=example_result):
            response = self.client.post(
                "/scan",
                data={**self.csrf, "url": "http://secure-login.example/path?token=private#fragment"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"HIGH RISK (Phishing)", response.data)
        self.assertIn(b"Classifier class 1 score", response.data)

        rows = self.query_database("SELECT url, classification FROM scans")
        self.assertEqual(rows, [("http://secure-login.example/path", "phishing")])

        restarted = application.create_app(
            {"TESTING": True, "SECRET_KEY": "test-secret", "DATABASE": str(self.database), "MODEL_PATH": str(self.model_path)}
        )
        restarted_client = restarted.test_client()
        detail_response = restarted_client.get("/history/1")
        self.assertEqual(detail_response.status_code, 200)
        self.assertIn(b"secure-login.example/path", detail_response.data)
        history_response = restarted_client.get("/history?q=secure-login&classification=phishing")
        self.assertEqual(history_response.status_code, 200)
        self.assertIn(b"secure-login.example/path", history_response.data)

    def test_empty_and_invalid_urls_show_validation_errors_without_saving(self):
        invalid_inputs = (
            ("", b"Enter a URL to scan."),
            ("javascript:alert(1)", b"Only HTTP and HTTPS"),
            ("https://user:secret@example.com", b"without embedded credentials"),
            ("https://example.com path", b"without spaces"),
        )
        for url, expected in invalid_inputs:
            response = self.client.post("/scan", data={**self.csrf, "url": url})
            self.assertEqual(response.status_code, 200)
            self.assertIn(expected, response.data)
        self.assertEqual(self.query_database("SELECT COUNT(*) FROM scans")[0][0], 0)

    def test_missing_model_runs_explicit_heuristic_fallback(self):
        response = self.client.post(
            "/scan", data={**self.csrf, "url": "http://secure-login-verify.example.com/account"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Heuristic-only result", response.data)
        self.assertIn(b"Classifier unavailable for this scan", response.data)
        record = self.query_database("SELECT model_used, risk_score FROM scans")[0]
        self.assertEqual(record[0], 0)
        self.assertGreaterEqual(record[1], 70)

    def test_message_analysis_is_not_persisted(self):
        text = "A private note asking to verify an account"
        empty_response = self.client.post("/message", data={**self.csrf, "message": ""})
        self.assertEqual(empty_response.status_code, 200)
        self.assertIn(b"Paste a message before analyzing it", empty_response.data)
        with patch("app.analyze_text", side_effect=example_result):
            response = self.client.post("/message", data={**self.csrf, "message": text})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"NOT SAVED", response.data)
        self.assertEqual(self.query_database("SELECT COUNT(*) FROM scans")[0][0], 0)

    def test_clear_history_requires_csrf_and_clears_records(self):
        with patch("app.analyze_text", side_effect=example_result):
            self.client.post("/scan", data={**self.csrf, "url": "https://example.com"})
        rejected = self.client.post("/history/clear", data={})
        self.assertEqual(rejected.status_code, 400)
        cleared = self.client.post("/history/clear", data=self.csrf, follow_redirects=True)
        self.assertEqual(cleared.status_code, 200)
        self.assertIn(b"Scan history cleared", cleared.data)
        self.assertEqual(self.query_database("SELECT COUNT(*) FROM scans")[0][0], 0)

    def test_json_scan_api_validates_csrf_and_returns_structured_result(self):
        response = self.client.post("/api/scan", json={"url": "https://example.com"})
        self.assertEqual(response.status_code, 400)
        malformed = self.client.post(
            "/api/scan", json=["https://example.com"], headers={"X-CSRF-Token": "test-csrf"}
        )
        self.assertEqual(malformed.status_code, 400)
        with patch("app.analyze_text", side_effect=example_result):
            response = self.client.post(
                "/api/scan", json={"url": "https://example.com"}, headers={"X-CSRF-Token": "test-csrf"}
            )
        self.assertEqual(response.status_code, 201)
        self.assertTrue(response.json["success"])
        self.assertIn("risk_score", response.json["scan"])

    def test_security_headers_are_present(self):
        response = self.client.get("/scan")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])

    def test_real_predictor_falls_back_without_model_and_never_fetches_urls(self):
        result = analyze_text("http://login-verify.example.com", model_path=self.model_path)
        self.assertFalse(result["model_used"])
        self.assertEqual(result["classification"], "phishing")
        self.assertEqual(result["urls"], ["http://login-verify.example.com"])

    def test_real_local_model_inference_when_weights_are_present(self):
        local_model = Path(application.PROJECT_ROOT) / "model" / "hf_model"
        if not (local_model / "model.safetensors").is_file():
            self.skipTest("Local model weights are not available in this checkout")
        result = analyze_text(
            "Meeting notes are available at https://example.com/agenda",
            model_path=local_model,
        )
        self.assertTrue(result["model_used"])
        self.assertIsInstance(result["class1_score"], float)
        self.assertGreaterEqual(result["class1_score"], 0)
        self.assertLessEqual(result["class1_score"], 100)


if __name__ == "__main__":
    unittest.main()
