"""
Layer 3 — Community Database
Auto-detects: uses PostgreSQL if available, else SQLite.
No manual config needed for local development.
"""

import json
import hashlib
import sqlite3
from datetime import datetime
from pathlib import Path
from config import DATABASE_URL

# ── DB Adapter ─────────────────────────────────────────────────────────────────
_USE_POSTGRES = False

if DATABASE_URL.startswith("postgresql") or DATABASE_URL.startswith("postgres"):
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        _test_url = DATABASE_URL.replace("postgres://", "postgresql://", 1)
        _conn = psycopg2.connect(_test_url, connect_timeout=3)
        _conn.close()
        _USE_POSTGRES = True
        print("✅ PostgreSQL connected")
    except Exception as e:
        print(f"⚠ PostgreSQL unavailable — using SQLite (local dev mode)")

if _USE_POSTGRES:
    PH = "%s"
    def get_db():
        url = DATABASE_URL.replace("postgres://", "postgresql://", 1)
        return psycopg2.connect(url, cursor_factory=RealDictCursor)
else:
    PH = "?"
    _SQLITE_PATH = Path(__file__).parent.parent / "uaintel.db"
    def get_db():
        conn = sqlite3.connect(str(_SQLITE_PATH))
        conn.row_factory = sqlite3.Row
        return conn


# ── Init ───────────────────────────────────────────────────────────────────────
def init_db():
    conn = get_db()
    c = conn.cursor()
    if _USE_POSTGRES:
        c.execute("""
            CREATE TABLE IF NOT EXISTS ua_records (
                id              SERIAL PRIMARY KEY,
                ua_hash         TEXT UNIQUE,
                ua_string       TEXT,
                first_seen      TEXT,
                last_seen       TEXT,
                total_lookups   INTEGER DEFAULT 1,
                malicious_votes INTEGER DEFAULT 0,
                benign_votes    INTEGER DEFAULT 0,
                bot_votes       INTEGER DEFAULT 0,
                risk_score      INTEGER DEFAULT 0,
                verdict         TEXT,
                rule_flags      TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS ua_reports (
                id          SERIAL PRIMARY KEY,
                ua_hash     TEXT,
                category    TEXT,
                comment     TEXT,
                reporter_ip TEXT,
                created_at  TEXT
            )
        """)
    else:
        c.execute("""
            CREATE TABLE IF NOT EXISTS ua_records (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                ua_hash         TEXT UNIQUE,
                ua_string       TEXT,
                first_seen      TEXT,
                last_seen       TEXT,
                total_lookups   INTEGER DEFAULT 1,
                malicious_votes INTEGER DEFAULT 0,
                benign_votes    INTEGER DEFAULT 0,
                bot_votes       INTEGER DEFAULT 0,
                risk_score      INTEGER DEFAULT 0,
                verdict         TEXT,
                rule_flags      TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS ua_reports (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ua_hash     TEXT,
                category    TEXT,
                comment     TEXT,
                reporter_ip TEXT,
                created_at  TEXT
            )
        """)
    conn.commit()
    conn.close()
    mode = "PostgreSQL" if _USE_POSTGRES else "SQLite"
    print(f"✅ Database initialized ({mode})")


def ua_hash(ua: str) -> str:
    return hashlib.sha256(ua.strip().encode()).hexdigest()[:16]


def store_ua_result(ua: str, risk_score: int, verdict: str, flags: list):
    conn = get_db()
    c = conn.cursor()
    h   = ua_hash(ua)
    now = datetime.utcnow().isoformat()
    flags_json = json.dumps(flags)
    try:
        if _USE_POSTGRES:
            c.execute("""
                INSERT INTO ua_records (ua_hash,ua_string,first_seen,last_seen,
                    total_lookups,risk_score,verdict,rule_flags)
                VALUES (%s,%s,%s,%s,1,%s,%s,%s)
                ON CONFLICT (ua_hash) DO UPDATE SET
                    last_seen=EXCLUDED.last_seen,
                    total_lookups=ua_records.total_lookups+1,
                    risk_score=EXCLUDED.risk_score,
                    verdict=EXCLUDED.verdict,
                    rule_flags=EXCLUDED.rule_flags
            """, (h, ua, now, now, risk_score, verdict, flags_json))
        else:
            row = c.execute(f"SELECT id FROM ua_records WHERE ua_hash=?", (h,)).fetchone()
            if row:
                c.execute("""UPDATE ua_records SET last_seen=?,total_lookups=total_lookups+1,
                    risk_score=?,verdict=?,rule_flags=? WHERE ua_hash=?""",
                    (now, risk_score, verdict, flags_json, h))
            else:
                c.execute("""INSERT INTO ua_records
                    (ua_hash,ua_string,first_seen,last_seen,total_lookups,
                     risk_score,verdict,rule_flags)
                    VALUES(?,?,?,?,1,?,?,?)""",
                    (h, ua, now, now, risk_score, verdict, flags_json))
        conn.commit()
    except Exception as e:
        print(f"store_ua_result error: {e}")
    finally:
        conn.close()


def get_community_stats(ua: str) -> dict:
    conn = get_db()
    c = conn.cursor()
    h = ua_hash(ua)
    try:
        c.execute(f"SELECT * FROM ua_records WHERE ua_hash={PH}", (h,))
        row = c.fetchone()
        c.execute(f"""SELECT category,comment,created_at FROM ua_reports
            WHERE ua_hash={PH} ORDER BY created_at DESC LIMIT 10""", (h,))
        comments = c.fetchall()
    finally:
        conn.close()

    if not row:
        return {"found": False, "comments": []}

    row = dict(row)
    mv = row.get("malicious_votes") or 0
    bv = row.get("benign_votes") or 0
    bov = row.get("bot_votes") or 0
    total_votes = mv + bv + bov
    confidence = round((mv / total_votes) * 100) if total_votes > 0 else 0

    return {
        "found":                True,
        "total_lookups":        row.get("total_lookups", 1),
        "first_seen":           (row.get("first_seen") or "")[:10],
        "last_seen":            (row.get("last_seen") or "")[:10],
        "malicious_votes":      mv,
        "benign_votes":         bv,
        "bot_votes":            bov,
        "total_votes":          total_votes,
        "confidence_malicious": confidence,
        "comments": [
            {"category":   dict(r)["category"],
             "comment":    dict(r)["comment"],
             "created_at": (dict(r)["created_at"] or "")[:16].replace("T", " ")}
            for r in comments if dict(r).get("comment")
        ]
    }


def submit_report(ua: str, category: str, comment: str, reporter_ip: str = "anonymous") -> bool:
    conn = get_db()
    c = conn.cursor()
    h   = ua_hash(ua)
    now = datetime.utcnow().isoformat()
    try:
        col_map = {"malicious": "malicious_votes", "benign": "benign_votes", "bot": "bot_votes"}
        col = col_map.get(category)
        if col:
            c.execute(f"UPDATE ua_records SET {col}={col}+1 WHERE ua_hash={PH}", (h,))
        if comment.strip():
            c.execute(f"""INSERT INTO ua_reports (ua_hash,category,comment,reporter_ip,created_at)
                VALUES({PH},{PH},{PH},{PH},{PH})""",
                (h, category, comment.strip(), reporter_ip, now))
        conn.commit()
        return True
    except Exception as e:
        print(f"submit_report error: {e}")
        return False
    finally:
        conn.close()


def get_recently_reported(limit: int = 15) -> list:
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute(f"""SELECT ua_string,verdict,risk_score,last_seen,
            malicious_votes,total_lookups FROM ua_records
            WHERE malicious_votes > 0 OR risk_score > 30
            ORDER BY last_seen DESC LIMIT {PH}""", (limit,))
        return [dict(r) for r in c.fetchall()]
    finally:
        conn.close()


def get_stats_summary() -> dict:
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute("SELECT COUNT(*) as cnt FROM ua_records")
        total = dict(c.fetchone() or {}).get("cnt", 0)
        c.execute("SELECT COUNT(*) as cnt FROM ua_records WHERE verdict IN ('Malicious','Likely Malicious')")
        malicious = dict(c.fetchone() or {}).get("cnt", 0)
        c.execute("SELECT COUNT(*) as cnt FROM ua_reports")
        reports = dict(c.fetchone() or {}).get("cnt", 0)
        return {"total_uas": total, "malicious_uas": malicious, "total_reports": reports}
    finally:
        conn.close()


# Init on import
try:
    init_db()
except Exception as e:
    print(f"DB init warning: {e}")