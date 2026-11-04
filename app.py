"""Flask application for URL triage and private, ephemeral message analysis."""

from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from flask import (
    Flask,
    abort,
    current_app,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    send_file,
    request,
    session,
    url_for,
)

from utils.predictor import analyze_text, model_status

PROJECT_ROOT = Path(__file__).resolve().parent
CHART_FILES = {
    "graph_metrics.png",
    "graph_confusion.png",
    "graph_distribution.png",
    "graph_keywords.png",
}
MAX_URL_LENGTH = 2048
MAX_MESSAGE_LENGTH = 12_000


class InvalidURL(ValueError):
    """Input validation error safe to show in the URL scanner."""


def _database_connection() -> sqlite3.Connection:
    if "db" not in g:
        database_path = current_app.config["DATABASE"]
        if database_path != ":memory:":
            Path(database_path).parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        g.db = connection
    return g.db


def _initialize_database(app: Flask) -> None:
    database_path = app.config["DATABASE"]
    if database_path != ":memory:":
        Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path, timeout=10)
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                hostname TEXT NOT NULL,
                classification TEXT NOT NULL CHECK(classification IN ('phishing', 'review', 'legitimate')),
                label TEXT NOT NULL,
                risk_score REAL NOT NULL,
                class1_score REAL,
                model_state TEXT NOT NULL,
                model_used INTEGER NOT NULL,
                observations TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.commit()
    finally:
        connection.close()


def _csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def _check_csrf() -> bool:
    supplied = request.headers.get("X-CSRF-Token") if request.is_json else request.form.get("csrf_token")
    expected = session.get("csrf_token", "")
    return bool(expected and supplied and hmac.compare_digest(expected, supplied))


def _validate_url(value: str) -> tuple[str, str, str]:
    raw = value.strip()
    if not raw:
        raise InvalidURL("Enter a URL to scan.")
    if len(raw) > MAX_URL_LENGTH:
        raise InvalidURL(f"URLs must be {MAX_URL_LENGTH:,} characters or fewer.")
    if any(character.isspace() or ord(character) < 32 for character in raw):
        raise InvalidURL("Enter one URL without spaces or line breaks.")
    explicit_scheme = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", raw)
    if explicit_scheme and explicit_scheme.group(1).lower() not in {"http", "https"}:
        raise InvalidURL("Only HTTP and HTTPS URLs can be analyzed.")
    candidate = raw if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw) else f"https://{raw}"
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise InvalidURL("That URL has an invalid host or port.") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise InvalidURL("Only HTTP and HTTPS URLs can be analyzed.")
    if not hostname or parsed.username is not None or parsed.password is not None:
        raise InvalidURL("Enter a URL with a hostname and without embedded credentials.")
    try:
        normalized_host = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise InvalidURL("That hostname is not valid.") from exc
    if ":" in normalized_host:
        try:
            normalized_host = ipaddress.IPv6Address(normalized_host).compressed
        except ipaddress.AddressValueError as exc:
            raise InvalidURL("That hostname is not valid.") from exc
    else:
        if not re.fullmatch(r"[a-z0-9.-]+", normalized_host) or normalized_host.startswith("."):
            raise InvalidURL("That hostname is not valid.")
        labels = normalized_host.rstrip(".").split(".")
        if any(not label or label.startswith("-") or label.endswith("-") for label in labels):
            raise InvalidURL("That hostname is not valid.")
    authority_host = f"[{normalized_host}]" if ":" in normalized_host else normalized_host
    authority = authority_host + (f":{port}" if port is not None else "")
    scheme = parsed.scheme.lower()
    canonical = urlunsplit((scheme, authority, parsed.path or "/", parsed.query, parsed.fragment))
    # Do not retain likely tracking tokens or fragments in the local scan history.
    history_url = urlunsplit((scheme, authority, parsed.path or "/", "", ""))
    return canonical, history_url, normalized_host


def _save_scan(url: str, hostname: str, result: dict) -> int:
    connection = _database_connection()
    cursor = connection.execute(
        """
        INSERT INTO scans
            (url, hostname, classification, label, risk_score, class1_score,
             model_state, model_used, observations, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            url,
            hostname,
            result["classification"],
            result["label"],
            result["risk_score"],
            result["class1_score"],
            result["model_state"],
            int(result["model_used"]),
            json.dumps(result["observations"]),
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
        ),
    )
    connection.commit()
    return int(cursor.lastrowid)


def _scan_payload(row: sqlite3.Row) -> dict:
    payload = dict(row)
    payload["observations"] = json.loads(payload["observations"])
    payload["model_used"] = bool(payload["model_used"])
    return payload


def _filtered_scans(search: str = "", classification: str = "", sort: str = "newest") -> list[dict]:
    clauses: list[str] = []
    parameters: list[str] = []
    if search:
        clauses.append("(url LIKE ? OR hostname LIKE ?)")
        term = f"%{search[:120]}%"
        parameters.extend((term, term))
    if classification in {"phishing", "review", "legitimate"}:
        clauses.append("classification = ?")
        parameters.append(classification)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    order = "ASC" if sort == "oldest" else "DESC"
    rows = _database_connection().execute(
        f"SELECT * FROM scans {where} ORDER BY created_at {order}, id {order} LIMIT 250",
        parameters,
    ).fetchall()
    return [_scan_payload(row) for row in rows]


def _dashboard_data() -> dict:
    connection = _database_connection()
    summary = connection.execute(
        """
        SELECT COUNT(*) AS total,
               SUM(classification = 'phishing') AS phishing,
               SUM(classification = 'legitimate') AS legitimate,
               SUM(classification = 'review') AS review,
               AVG(risk_score) AS average_score
        FROM scans
        """
    ).fetchone()
    recent = [
        _scan_payload(row)
        for row in connection.execute(
            "SELECT * FROM scans ORDER BY created_at DESC, id DESC LIMIT 6"
        ).fetchall()
    ]
    scores = [row[0] for row in connection.execute("SELECT risk_score FROM scans").fetchall()]
    ranges = [(0, 20), (20, 40), (40, 60), (60, 80), (80, 101)]
    distribution = [
        {"label": f"{start}–{min(end - 1, 100)}", "count": sum(start <= score < end for score in scores)}
        for start, end in ranges
    ]
    total = int(summary["total"] or 0)
    return {
        "total": total,
        "phishing": int(summary["phishing"] or 0),
        "legitimate": int(summary["legitimate"] or 0),
        "review": int(summary["review"] or 0),
        "average_score": round(summary["average_score"], 1) if summary["average_score"] is not None else None,
        "recent": recent,
        "distribution": distribution,
        "max_bin": max((item["count"] for item in distribution), default=0),
    }


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        DATABASE=os.environ.get("PHISHING_DATABASE") or str(Path(app.instance_path) / "scans.sqlite3"),
        MODEL_PATH=os.environ.get("PHISHING_MODEL_PATH") or str(PROJECT_ROOT / "model" / "hf_model"),
        MAX_CONTENT_LENGTH=64 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    if test_config:
        app.config.update(test_config)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    _initialize_database(app)
    app.jinja_env.globals["csrf_token"] = _csrf_token

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("phishing_detector")

    @app.teardown_appcontext
    def close_db(_exception=None):
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "font-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
        )
        return response

    @app.context_processor
    def shared_template_data():
        return {"model_status": model_status(app.config["MODEL_PATH"])}

    def analyze_input(text: str) -> dict:
        return analyze_text(text, model_path=app.config["MODEL_PATH"])

    def require_form_csrf():
        if not _check_csrf():
            abort(400, description="Your form session expired. Refresh the page and try again.")

    @app.get("/")
    def overview():
        config_path = Path(app.config["MODEL_PATH"]) / "config.json"
        architecture = "Sequence classifier"
        if config_path.is_file():
            try:
                architecture = (json.loads(config_path.read_text(encoding="utf-8")).get("architectures") or [architecture])[0]
            except (OSError, json.JSONDecodeError):
                pass
        return render_template(
            "dashboard.html", page_title="Security overview", dashboard=_dashboard_data(),
            model_architecture=architecture,
        )

    @app.route("/scan", methods=["GET", "POST"])
    def scan_url():
        result = None
        submitted_url = ""
        saved_id = None
        error = None
        result_timestamp = None
        if request.method == "POST":
            require_form_csrf()
            submitted_url = request.form.get("url", "")
            try:
                canonical_url, history_url, hostname = _validate_url(submitted_url)
                result = analyze_input(canonical_url)
                saved_id = _save_scan(history_url, hostname, result)
                result_timestamp = datetime.now(timezone.utc).strftime("%d %b %Y · %H:%M")
                logger.info("URL scan completed: id=%s class=%s", saved_id, result["classification"])
            except InvalidURL as exc:
                error = str(exc)
                logger.info("URL scan rejected: validation")
            except Exception as exc:
                error = "The scan could not be completed. Check the local model setup and try again."
                logger.warning("URL scan failed (%s)", type(exc).__name__)
        return render_template(
            "scanner.html", page_title="URL scanner", result=result,
            submitted_url=submitted_url, saved_id=saved_id, error=error,
            result_timestamp=result_timestamp,
        )

    @app.route("/message", methods=["GET", "POST"])
    def message_analyzer():
        result = None
        message = ""
        error = None
        if request.method == "POST":
            require_form_csrf()
            message = request.form.get("message", "")
            if not message.strip():
                error = "Paste a message before analyzing it."
            elif len(message) > MAX_MESSAGE_LENGTH:
                error = f"Messages must be {MAX_MESSAGE_LENGTH:,} characters or fewer."
            else:
                try:
                    result = analyze_input(message)
                    logger.info("Message analysis completed; message body was not stored")
                except Exception as exc:
                    error = "The message could not be analyzed. Check the local model setup and try again."
                    logger.warning("Message analysis failed (%s)", type(exc).__name__)
        return render_template(
            "message.html", page_title="Message analyzer", result=result, message=message, error=error
        )

    @app.get("/history")
    def history():
        search = request.args.get("q", "").strip()
        classification = request.args.get("classification", "")
        sort = request.args.get("sort", "newest")
        scans = _filtered_scans(search, classification, sort)
        return render_template(
            "history.html", page_title="Scan history", scans=scans,
            search=search, classification=classification, sort=sort,
        )

    @app.get("/history/<int:scan_id>")
    def scan_detail(scan_id: int):
        row = _database_connection().execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            abort(404)
        return render_template("scan_detail.html", page_title="Scan details", scan=_scan_payload(row))

    @app.post("/history/clear")
    def clear_history():
        require_form_csrf()
        _database_connection().execute("DELETE FROM scans")
        _database_connection().commit()
        flash("Scan history cleared.", "success")
        logger.info("Scan history cleared")
        return redirect(url_for("history"))

    @app.get("/model")
    def model_analytics():
        status = model_status(app.config["MODEL_PATH"])
        config = {}
        config_path = Path(app.config["MODEL_PATH"]) / "config.json"
        if config_path.is_file():
            try:
                config = json.loads(config_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                config = {}
        architecture = (config.get("architectures") or ["Sequence classifier"])[0]
        return render_template(
            "model.html", page_title="Model & evaluation", status=status,
            model_config=config, architecture=architecture,
        )

    @app.get("/settings")
    def settings():
        configured_model_path = Path(app.config["MODEL_PATH"])
        if not configured_model_path.is_absolute():
            configured_model_path = PROJECT_ROOT / configured_model_path
        try:
            model_path_label = configured_model_path.resolve().relative_to(PROJECT_ROOT).as_posix() + "/"
        except ValueError:
            model_path_label = "Custom local directory (PHISHING_MODEL_PATH)"
        return render_template(
            "settings.html", page_title="System settings",
            database_ready=Path(app.config["DATABASE"]).exists() or app.config["DATABASE"] == ":memory:",
            model_path_label=model_path_label,
        )

    @app.get("/assets/<path:filename>")
    def project_chart(filename: str):
        if filename not in CHART_FILES:
            abort(404)
        return send_file(PROJECT_ROOT / filename, mimetype="image/png", conditional=True)

    @app.post("/api/scan")
    def api_scan():
        if not request.is_json:
            return jsonify(error="Send a JSON request."), 415
        if not _check_csrf():
            return jsonify(error="Refresh the page and retry the request."), 400
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            return jsonify(error="Send a JSON object with a url field."), 400
        raw_url = data.get("url", "")
        if not isinstance(raw_url, str):
            return jsonify(error="The url field must be text."), 400
        try:
            canonical_url, history_url, hostname = _validate_url(raw_url)
            result = analyze_input(canonical_url)
            scan_id = _save_scan(history_url, hostname, result)
            return jsonify(success=True, scan={"id": scan_id, "url": canonical_url, **result}), 201
        except InvalidURL as exc:
            return jsonify(error=str(exc)), 400
        except Exception as exc:
            logger.warning("API URL scan failed (%s)", type(exc).__name__)
            return jsonify(error="The scan could not be completed."), 500

    @app.get("/api/scans")
    def api_scans():
        scans = _filtered_scans(
            request.args.get("q", ""),
            request.args.get("classification", ""),
            request.args.get("sort", "newest"),
        )
        return jsonify(scans=scans)

    @app.errorhandler(400)
    def bad_request(error):
        if request.path.startswith("/api/"):
            return jsonify(error=error.description or "Invalid request."), 400
        return render_template("error.html", page_title="Request needs attention", code=400,
                              message=error.description or "Please refresh and try again."), 400

    @app.errorhandler(404)
    def not_found(_error):
        if request.path.startswith("/api/"):
            return jsonify(error="Not found."), 404
        return render_template("error.html", page_title="Page not found", code=404,
                              message="That page or scan does not exist."), 404

    @app.errorhandler(413)
    def request_too_large(_error):
        if request.path.startswith("/api/"):
            return jsonify(error="Request is too large."), 413
        return render_template("error.html", page_title="Input too large", code=413,
                              message="The submitted request is too large."), 413

    @app.errorhandler(500)
    def server_error(_error):
        logger.error("Unhandled server error at %s", request.path)
        if request.path.startswith("/api/"):
            return jsonify(error="An internal error occurred."), 500
        return render_template("error.html", page_title="Something went wrong", code=500,
                              message="The request could not be completed. Please try again."), 500

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
