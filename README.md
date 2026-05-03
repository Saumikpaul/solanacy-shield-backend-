# Security Audit Tool — Backend

Python/Flask backend for the ethical security audit platform.

## Structure

```
security-audit-backend/
├── main.py                    # Flask app entry point
├── requirements.txt           # Dependencies
├── render.yaml                # Render.com deployment config
├── .env.example               # Environment variable template
├── routes/
│   ├── ping.py                # Health check & server alive
│   ├── auth.py                # Firebase token verification
│   ├── scan.py                # Scan orchestration
│   └── report.py              # Report fetch endpoints
├── scanners/
│   ├── ssl_check.py           # SSL/TLS certificate check
│   ├── headers_check.py       # HTTP security headers
│   ├── port_scan.py           # Open port detection (nmap)
│   ├── sqli_check.py          # SQL injection test
│   ├── xss_check.py           # XSS reflection test
│   ├── dir_scan.py            # Exposed files/directories
│   └── blacklist_check.py     # Google Safe Browsing + DNSBL
├── ai/
│   └── report_generator.py    # Gemma 4 31B report generation
└── utils/
    ├── domain_verify.py        # DNS TXT ownership verification
    └── firebase_admin.py       # Firestore (placeholder — add SDK)
```

## Setup

1. Copy `.env.example` to `.env` and fill in your values
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run locally:
   ```bash
   python main.py
   ```

## API Keys Needed

| Key | Where to Get | Cost |
|-----|-------------|------|
| `GEMINI_API_KEY` | [Google AI Studio](https://aistudio.google.com/apikey) | Free tier |
| `SAFE_BROWSING_API_KEY` | [Google Cloud Console](https://developers.google.com/safe-browsing/v4/get-started) | Free |
| Firebase SDK | [Firebase Console](https://console.firebase.google.com) | Free tier |

## Deploy to Render

1. Push to GitHub
2. Connect Render to your repo
3. Use `render.yaml` settings
4. Add env vars in Render dashboard

## Frontend Ping (Keep Server Alive)

Add this to your frontend JS:
```javascript
// Keep Render free tier alive
setInterval(() => {
  fetch("https://your-render-url.onrender.com/ping")
    .catch(() => {}); // Ignore errors silently
}, 10 * 60 * 1000); // Every 10 minutes
```

## Firebase Setup (When Ready)

1. Go to Firebase Console → Project Settings → Service Accounts
2. Generate new private key
3. Add all values to `.env`
4. Uncomment Firebase code in `utils/firebase_admin.py`
5. Add `firebase-admin` to `requirements.txt`
6. Uncomment Firebase verification in `routes/auth.py`
