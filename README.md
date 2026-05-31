# UAIntel v3.2 — User-Agent Intelligence Platform

## Detection Layers
```
Layer 1 → Rule Engine          Instant, zero cost, keyword + regex
Layer 2 → 6 GitHub Databases   15,000+ patterns, auto-updating weekly
Layer 3 → Community Database   Crowdsourced votes + comments (PostgreSQL)
```

## Databases (Auto-Downloaded on Startup)
| Source | Entries | Type |
|--------|---------|------|
| mitchellkrogza/nginx-bad-bot-blocker | ~5,000 | Bad bots |
| mitchellkrogza/apache-bad-bot-blocker | ~5,000 | Bad bots |
| mitchellkrogza/UltimateBadBots | ~2,000 | Bad bots |
| mthcht/awesome-lists | ~700 | Malware UAs with categories |
| monperrus/crawler-user-agents | ~1,200 | Legit crawlers |
| matomo/device-detector | ~500 | Classified bots |

**Total: ~14,000–15,000 patterns**

## Local Development
```bash
pip install -r requirements.txt
cd backend
python main.py
# Opens at http://localhost:8000
# Uses SQLite automatically (no setup needed)
```

## Deploy to Render.com (Free)

### Step 1 — Push to GitHub
```bash
git init
git add .
git commit -m "UAIntel v3.2"
git remote add origin https://github.com/YOUR_USERNAME/uaintel.git
git push -u origin main
```

### Step 2 — Deploy on Render.com
1. Go to render.com → New → Blueprint
2. Connect your GitHub repo
3. Render reads render.yaml automatically
4. Creates: Web Service + PostgreSQL (free)
5. Click Deploy — done!

### Step 3 — Set up Auto-Update Cron (Free)
1. Go to cron-job.org (free account)
2. Create new cron job:
   - URL: https://your-app.onrender.com/db-update
   - Method: POST
   - Schedule: Every Sunday at 02:00
3. Done — databases update automatically every week!

## API Endpoints
```
POST /analyze        Analyze a User-Agent string
POST /report         Submit community report  
GET  /recent         Recently reported UAs
GET  /stats          Platform statistics
GET  /db-status      Database status + entry counts
POST /db-update      Trigger manual database update
GET  /health         Health check
```

## Risk Score
| Score | Verdict |
|-------|---------|
| 0–20  | Legitimate |
| 21–50 | Suspicious |
| 51–75 | Likely Malicious |
| 76–100| Malicious |
