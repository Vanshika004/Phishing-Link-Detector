# Phishing Link Detector

A complete local cybersecurity demo with a Chrome Manifest V3 extension, a Flask API, heuristic phishing detection, and optional VirusTotal integration.

## Project Structure

```text
.
|-- manifest.json
|-- background.js
|-- content.js
|-- popup.html
|-- popup.js
|-- options.html
|-- options.js
|-- style.css
|-- app.py
|-- requirements.txt
|-- test.html
`-- utils/
    `-- detector.py
```

## Run The Flask Backend

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

The API runs at:

```text
http://localhost:5000/api/check-url
```

Health check:

```text
http://localhost:5000/api/health
```

## Set VirusTotal API Key

VirusTotal is optional. The backend still uses heuristic checks when no key is set.

PowerShell, current terminal only:

```powershell
$env:VIRUSTOTAL_API_KEY="your_api_key_here"
python app.py
```

Command Prompt, current terminal only:

```cmd
set VIRUSTOTAL_API_KEY=your_api_key_here
python app.py
```

Persistent user environment variable:

```cmd
setx VIRUSTOTAL_API_KEY "your_api_key_here"
```

Open a new terminal after using `setx`.

## Install The Chrome Extension

1. Open Chrome and go to `chrome://extensions`.
2. Enable `Developer mode`.
3. Click `Load unpacked`.
4. Select this project folder:

```text
C:\Users\Vanshika\Desktop\Phishing Link Detector ext
```

5. Start the Flask backend before testing the extension.

## Testing The Extension

Use the included `test.html` page for a safe local demo.

1. Start the Flask backend:

```powershell
python app.py
```

2. Open this file in Chrome:

```text
C:\Users\Vanshika\Desktop\Phishing Link Detector ext\test.html
```

3. If Chrome blocks extension access on local files:

- Go to `chrome://extensions`.
- Open `Phishing Link Detector` details.
- Enable `Allow access to file URLs`.
- Refresh `test.html`.

4. Expected behavior:

- `Safe example website` should remain normal.
- `Login update verification` should get a red border.
- The hidden phishing-style link should increase the flagged link count.
- The extension popup should show `Phishing`, a risk score, flagged link count, and explanation reasons.
- The extension badge should show the number of flagged links.

5. Click protection test:

- Click the red `Login update verification` link only to demonstrate protection.
- When the warning appears, click `Cancel`.
- Clicking `OK` will try to open the fake IP URL and may show `This site can't be reached`.
- That error page is expected because the phishing test link is not a real website.

6. View backend logs:

```powershell
type phishing_detector.log
```

You should see scanned URLs, results, scores, and detection reasons.

## Make It Accessible To Other Users

Other users cannot use your local `localhost` backend. To make the extension work for everyone:

1. Deploy the Flask backend to a public hosting service such as Render, Railway, PythonAnywhere, or a VPS.
2. Set `VIRUSTOTAL_API_KEY` in that hosting service's environment variables.
3. Confirm the deployed backend works by opening:

```text
https://your-backend-domain.com/api/health
```

4. In Chrome, open the extension details and click `Extension options`.
5. Set the backend URL to your deployed backend, for example:

```text
https://your-backend-domain.com
```

6. Share the extension folder as a zip for manual installation, or publish it on the Chrome Web Store.

For public deployment, run Flask with:

```powershell
$env:PUBLIC_SERVER="true"
$env:FLASK_DEBUG="false"
$env:ALLOWED_ORIGINS="chrome-extension://your_extension_id"
python app.py
```

On hosting platforms, set these environment variables in the provider dashboard instead of PowerShell.

Security-related environment variables:

```text
VIRUSTOTAL_API_KEY      Required for VirusTotal checks
PUBLIC_SERVER=true      Allows Flask to bind publicly
FLASK_DEBUG=false       Keeps debug mode off in deployment
ALLOWED_ORIGINS         Comma-separated trusted origins for CORS
TRUST_PROXY_HEADERS     Set true only behind a trusted reverse proxy
```

## How It Works

- `content.js` scans all `<a>` tags on the page.
- Scanning starts automatically whenever a page opens.
- Each URL is sent to `POST http://localhost:5000/api/check-url` with its text and hidden-link status.
- The backend returns `Safe`, `Suspicious`, or `Phishing` with a score and reasons.
- Suspicious links receive an orange border.
- Phishing links receive a red border and light red background.
- Suspicious and phishing links show a warning before navigation.
- Suspicious and phishing detections trigger an automatic on-page alert popup.
- The extension badge shows the number of flagged links on the current tab.
- A `MutationObserver` scans links added after page load.
- The popup shows the current page, scan status, latest score, flagged link count, and explanation reasons.
- Hidden or invisible links increase the risk score.
- Flask logs scanned URLs and detections to `phishing_detector.log`.
- A simple in-memory rate limiter blocks excessive requests.

## API Example

Request:

```json
{
  "url": "https://example.com/login",
  "text": "Account login",
  "hidden": false
}
```

Response:

```json
{
  "result": "Suspicious",
  "score": 3,
  "reasons": ["Contains suspicious keyword(s): login"]
}
```

## Scoring

The score is a weighted risk score, not a fixed percentage.

```text
0 - 2     Safe
3 - 5     Suspicious
6+        Phishing
```

Examples of scoring rules:

```text
@ in URL                         +2
URL length > 75                  +1
Suspicious keywords              +1 each
IP address instead of domain     +2
Too many hyphens                 +1
No HTTPS                         +1
Repeated characters              +1
Hidden/invisible link            +2
No visible link text             +1
VirusTotal malicious             +4
VirusTotal suspicious            +2
```

## Security Notes

- The VirusTotal API key is read only by the Flask backend.
- The frontend never receives or stores the API key.
- The backend validates URLs before analysis.
- VirusTotal errors are handled gracefully and returned as non-fatal reasons.
- Flask limits request body size to reduce abuse.
- CORS is restricted to trusted extension/local origins instead of being fully open.
- Logs remove URL query strings to avoid storing sensitive tokens.
- Do not commit real API keys to GitHub.
- Keep `.env`, logs, `__pycache__`, and `.pyc` files out of public repositories.
