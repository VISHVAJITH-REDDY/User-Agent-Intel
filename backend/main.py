"""
UAIntel v3.2 — Production FastAPI Application
"""
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional
from collections import defaultdict
import time
from pathlib import Path

from config import ALLOWED_HOSTS, RATE_LIMIT_ANALYZE, RATE_LIMIT_REPORT, FRONTEND_DIR
from analyzer import analyze_ua
from db_engine import (run_db_checks, download_databases, get_db_status,
                       check_databases_exist, any_database_exists,
                       start_scheduler, stop_scheduler, needs_update,
                       load_databases_into_memory)
from community_db import (store_ua_result, get_community_stats,
                          submit_report, get_recently_reported, get_stats_summary)
from score_combiner import combine_scores

app = FastAPI(
    title="UAIntel — User-Agent Intelligence",
    description="Analyze and report malicious User-Agent strings",
    version="3.2.0",
)

# ── CORS ───────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ── Rate Limiting (in-memory, resets on restart) ───────────────────────────────
_rate_store: dict = defaultdict(list)

def is_rate_limited(ip: str, endpoint: str, limit: int) -> bool:
    key   = f"{ip}:{endpoint}"
    now   = time.time()
    calls = [t for t in _rate_store[key] if now - t < 60]  # last 60 seconds
    _rate_store[key] = calls
    if len(calls) >= limit:
        return True
    _rate_store[key].append(now)
    return False


def get_client_ip(request: Request) -> str:
    # Respect X-Forwarded-For on Render.com / behind proxy
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ── Startup / Shutdown ─────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    print("🚀 UAIntel v3.2 starting up...")

    # Download DBs if missing or stale
    if not check_databases_exist() or needs_update():
        print("📥 Downloading / updating databases...")
        results = await download_databases()
        for k, v in results.items():
            print(f"  {'✅' if v.get('success') else '❌'} {k}")
    elif any_database_exists():
        print("📂 Loading existing databases...")
        load_databases_into_memory()

    # Start weekly auto-update scheduler
    start_scheduler()
    print("✅ UAIntel ready!")


@app.on_event("shutdown")
async def shutdown():
    stop_scheduler()


# ── Models ─────────────────────────────────────────────────────────────────────
class UARequest(BaseModel):
    user_agent: str

class ReportRequest(BaseModel):
    user_agent: str
    category:   str           # malicious | benign | bot
    comment:    Optional[str] = ""


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.post("/analyze")
async def analyze(req: UARequest, request: Request):
    ip = get_client_ip(request)
    if is_rate_limited(ip, "analyze", RATE_LIMIT_ANALYZE):
        return JSONResponse({"error": f"Rate limit exceeded. Max {RATE_LIMIT_ANALYZE} requests/minute."}, status_code=429)

    ua = req.user_agent.strip()
    if not ua:
        return JSONResponse({"error": "User-Agent string cannot be empty"}, status_code=400)
    if len(ua) > 2000:
        return JSONResponse({"error": "User-Agent string too long (max 2000 chars)"}, status_code=400)

    # Layer 1
    rule_result = analyze_ua(ua)
    # Layer 2
    db_result   = run_db_checks(ua)
    # Layer 3
    community   = get_community_stats(ua)
    # Combine
    combined    = combine_scores(rule_result, db_result, community)

    # Persist
    store_ua_result(ua, combined["risk_score"], combined["verdict"],
                    [f["label"] for f in combined["flags"]])

    return {
        "parsed":            rule_result["parsed"],
        "flags":             combined["flags"],
        "flag_count":        combined["flag_count"],
        "risk_score":        combined["risk_score"],
        "verdict":           combined["verdict"],
        "verdict_color":     combined["verdict_color"],
        "detection_sources": combined["detection_sources"],
        "score_breakdown":   combined["score_breakdown"],
        "db_loaded":         combined["db_loaded"],
        "db_counts":         combined["db_counts"],
        "community":         community,
        "crawler":           rule_result.get("crawler"),
    }


@app.post("/report")
async def report(req: ReportRequest, request: Request):
    ip = get_client_ip(request)
    if is_rate_limited(ip, "report", RATE_LIMIT_REPORT):
        return JSONResponse({"error": "Rate limit exceeded."}, status_code=429)
    if req.category not in ("malicious", "benign", "bot"):
        return JSONResponse({"error": "category must be: malicious, benign, or bot"}, status_code=400)

    submit_report(req.user_agent, req.category, req.comment or "", ip)
    return {"success": True, "message": "Report submitted — thank you!"}


@app.get("/recent")
def recent():
    return {"results": get_recently_reported(15)}


@app.get("/stats")
def stats():
    return get_stats_summary()


@app.get("/db-status")
def db_status():
    return get_db_status()


@app.post("/db-update")
async def db_update(background_tasks: BackgroundTasks, request: Request):
    ip = get_client_ip(request)
    if is_rate_limited(ip, "db-update", 3):
        return JSONResponse({"error": "Rate limit exceeded."}, status_code=429)
    background_tasks.add_task(download_databases)
    return {"message": "Database update started in background. Check /db-status in ~30 seconds."}


@app.get("/health")
def health():
    return {"status": "ok", "service": "UAIntel", "version": "3.2.0"}


# ── Frontend ───────────────────────────────────────────────────────────────────
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/")
    def frontend():
        return FileResponse(str(FRONTEND_DIR / "index.html"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
