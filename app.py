import logging
import os
import time
from collections import defaultdict, deque

from flask import Flask, jsonify, request

from utils.detector import detect_url, is_valid_url


app = Flask(__name__)
logging.basicConfig(
    filename="phishing_detector.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 120
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


@app.after_request
def add_cors_headers(response):
    """Allow the Chrome extension to call this local development API."""
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    return response


@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({"status": "ok", "service": "phishing-link-detector"})


@app.route("/api/check-url", methods=["POST", "OPTIONS"])
def check_url():
    if request.method == "OPTIONS":
        return ("", 204)

    client_id = request.headers.get("X-Forwarded-For", request.remote_addr or "local")
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
        logging.info("Invalid URL submitted client=%s url=%r", client_id, url)
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
        url,
        "; ".join(analysis["reasons"]),
    )
    return jsonify(analysis)


if __name__ == "__main__":
    host = "0.0.0.0" if os.getenv("PUBLIC_SERVER") == "true" else "127.0.0.1"
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "true").lower() == "true"
    app.run(host=host, port=port, debug=debug)
