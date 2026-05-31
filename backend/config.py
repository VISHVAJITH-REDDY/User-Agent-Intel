"""
UAIntel Configuration
All settings pulled from environment variables.
Copy .env.example to .env and fill in values.
"""
import os

# ── Database ───────────────────────────────────────────────────────────────────
# PostgreSQL connection string
# Render.com provides this automatically as DATABASE_URL
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/uaintel"
)

# ── App ────────────────────────────────────────────────────────────────────────
APP_ENV       = os.environ.get("APP_ENV", "development")   # development | production
SECRET_KEY    = os.environ.get("SECRET_KEY", "change-this-in-production-please")
ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "*").split(",")

# ── Rate Limiting ──────────────────────────────────────────────────────────────
RATE_LIMIT_ANALYZE = int(os.environ.get("RATE_LIMIT_ANALYZE", "30"))   # per minute per IP
RATE_LIMIT_REPORT  = int(os.environ.get("RATE_LIMIT_REPORT",  "10"))   # per minute per IP

# ── Auto-Update ────────────────────────────────────────────────────────────────
DB_AUTO_UPDATE_DAYS = int(os.environ.get("DB_AUTO_UPDATE_DAYS", "7"))  # re-download every N days

# ── Paths ──────────────────────────────────────────────────────────────────────
from pathlib import Path
BASE_DIR      = Path(__file__).parent.parent
DB_DIR        = BASE_DIR / "databases"
FRONTEND_DIR  = BASE_DIR / "frontend"
DB_DIR.mkdir(exist_ok=True)
