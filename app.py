import logging
import os
import time
from collections import defaultdict, deque
from urllib.parse import urlsplit, urlunsplit

from flask import Flask, jsonify, request

from utils.detector import detect_url, is_valid_url


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
logging.basicConfig(
    filename="phishing_detector.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 120
DEFAULT_ALLOWED_ORIGINS = {
    "chrome-extension://",
    "http://localhost",
    "http://127.0.0.1",
    "file://",
}
request_times = defaultdict(deque)


def is_rate_limited(client_id):
    now = time.time()
    timestamps = request_times[client_id]

    while timestamps and now - timestamps[0] > RATE_LIMIT_WINDOW_SECONDS:
        timestamps.popleft()

    if len(timestamps) >= RATE_LIMIT_MAX_REQUESTS:
        return True

    timestamps.append(now)
    return False


def get_client_id():
    # Do not trust X-Forwarded-For unless the app is explicitly behind a trusted proxy.
    if os.getenv("TRUST_PROXY_HEADERS", "false").lower() == "true":
        forwarded_for = request.headers.get("X-Forwarded-For", "")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

    return request.remote_addr or "local"


def is_origin_allowed(origin):
    if not origin:
        return True

    configured = os.getenv("ALLOWED_ORIGINS", "")
    allowed_origins = {item.strip() for item in configured.split(",") if item.strip()}

    if origin in allowed_origins:
        return True

    return any(origin.startswith(prefix) for prefix in DEFAULT_ALLOWED_ORIGINS)


def safe_log_url(url):
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


@app.after_request
def add_cors_headers(response):
    """Allow trusted extension/local origins to call the API."""
    origin = request.headers.get("Origin")
    if is_origin_allowed(origin):
        response.headers["Access-Control-Allow-Origin"] = origin or "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    response.headers["Vary"] = "Origin"
    return response


@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({"status": "ok", "service": "phishing-link-detector"})


@app.route("/api/check-url", methods=["POST", "OPTIONS"])
def check_url():
    if request.method == "OPTIONS":
        if not is_origin_allowed(request.headers.get("Origin")):
            return jsonify({"error": "Origin not allowed"}), 403
        return ("", 204)

    if not is_origin_allowed(request.headers.get("Origin")):
        return jsonify({"error": "Origin not allowed"}), 403

    client_id = get_client_id()
    if is_rate_limited(client_id):
        logging.warning("Rate limit exceeded for client=%s", client_id)
        return (
            jsonify(
                {
                    "result": "Suspicious",
                    "score": 3,
                    "reasons": ["Rate limit exceeded. Please slow down scanning requests."],
                }
            ),
            429,
        )

    payload = request.get_json(silent=True) or {}
    url = payload.get("url", "")
    link_text = payload.get("text", "")
    hidden = bool(payload.get("hidden", False))

    if not is_valid_url(url):
        logging.info("Invalid URL submitted client=%s url=%r", client_id, safe_log_url(str(url)))
        return jsonify(
            {
                "result": "Suspicious",
                "score": 3,
                "reasons": ["Invalid or unsupported URL"],
            }
        )

    analysis = detect_url(url, hidden=hidden, link_text=link_text)
    logging.info(
        "Scanned URL client=%s result=%s score=%s hidden=%s url=%s reasons=%s",
        client_id,
        analysis["result"],
        analysis["score"],
        hidden,
        safe_log_url(url),
        "; ".join(analysis["reasons"]),
    )
    return jsonify(analysis)


if __name__ == "__main__":
    host = "0.0.0.0" if os.getenv("PUBLIC_SERVER") == "true" else "127.0.0.1"
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host=host, port=port, debug=debug)
