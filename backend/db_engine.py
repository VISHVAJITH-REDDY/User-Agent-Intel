"""
Layer 2 — Database Engine (v3.2 DEFINITIVE)

Confirmed sources & parsers:
  1. nginx-ultimate-bad-bot-blocker  bots.d/blacklist-user-agents.conf  ~683 UA names
  2. apache-ultimate-bad-bot-blocker _generator_lists/bad-user-agents.list ~683 UA names
  3. SecLists UserAgents.fuzz.txt                                         ~3,000+ UAs
  4. mthcht suspicious_http_user_agents_list.csv                          ~1,555 malware UAs
  5. monperrus crawler-user-agents.json                                   ~1,767 legit crawlers
  6. matomo Bots.php                                                       ~200 bots

Honest total: ~7,000+ patterns
"""

import httpx
import json
import csv
import io
import re
from datetime import datetime, timedelta
from pathlib import Path
from config import DB_DIR

VERSIONS_FILE = DB_DIR / "versions.json"
DB_DIR.mkdir(exist_ok=True)

SOURCES = {
    "nginx_bots": {
        "url":      "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/bots.d/blacklist-user-agents.conf",
        "fallback": "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list",
        "file":     DB_DIR / "nginx_bots.txt",
        "desc":     "Nginx Bad Bot Blocker",
        "parse":    "conf",
    },
    "apache_bots": {
        "url":      "https://raw.githubusercontent.com/mitchellkrogza/apache-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list",
        "fallback": "https://raw.githubusercontent.com/mitchellkrogza/apache-ultimate-bad-bot-blocker/master/bots.d/blacklist-user-agents.conf",
        "file":     DB_DIR / "apache_bots.txt",
        "desc":     "Apache Bad Bot Blocker",
        "parse":    "plaintext",
    },
    "seclists_ua": {
        "url":      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/User-Agents/UserAgents.fuzz.txt",
        "fallback": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Miscellaneous/User-Agents/user_agents.txt",
        "file":     DB_DIR / "seclists_ua.txt",
        "desc":     "SecLists UA Database",
        "parse":    "plaintext",
    },
    "mthcht_malware": {
        "url":      "https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/suspicious_http_user_agents_list.csv",
        "fallback": None,
        "file":     DB_DIR / "mthcht_malware.csv",
        "desc":     "mthcht Malware UA Intelligence",
        "parse":    "csv",
    },
    "crawlers": {
        "url":      "https://raw.githubusercontent.com/monperrus/crawler-user-agents/master/crawler-user-agents.json",
        "fallback": None,
        "file":     DB_DIR / "crawlers.json",
        "desc":     "Crawler UA Database",
        "parse":    "json_crawlers",
    },
    "matomo_bots": {
        "url":      "https://raw.githubusercontent.com/matomo-org/device-detector/master/regexes/bots.yml",
        "fallback": "https://raw.githubusercontent.com/matomo-org/device-detector/master/Tests/fixtures/bots.yml",
        "file":     DB_DIR / "matomo_bots.txt",
        "desc":     "Matomo Device Detector",
        "parse":    "yaml",
    },
}

# ── In-memory ──────────────────────────────────────────────────────────────────
_bad_bots_set  = set()
_bad_bots_list = []
_malware_map   = {}
_crawler_list  = []
_matomo_bots   = []
_db_loaded     = False
_scheduler     = None


# ── Versions ───────────────────────────────────────────────────────────────────
def load_versions() -> dict:
    try:
        if VERSIONS_FILE.exists():
            return json.loads(VERSIONS_FILE.read_text())
    except:
        pass
    return {}

def save_versions(v: dict):
    try:
        VERSIONS_FILE.write_text(json.dumps(v, indent=2))
    except:
        pass


# ── Download ───────────────────────────────────────────────────────────────────
async def download_databases() -> dict:
    versions = load_versions()
    results  = {}
    print("Downloading databases from GitHub...")

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        for key, src in SOURCES.items():
            urls = [src["url"]] + ([src["fallback"]] if src.get("fallback") else [])
            downloaded = False
            for url in urls:
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200 and len(resp.content) > 100:
                        src["file"].write_bytes(resp.content)
                        versions[f"{key}_updated"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
                        results[key] = {"success": True, "bytes": len(resp.content)}
                        print(f"  OK {key}: {len(resp.content):,} bytes from {url}")
                        downloaded = True
                        break
                    else:
                        print(f"  FAIL {key}: HTTP {resp.status_code} at {url}")
                        results[key] = {"success": False, "error": f"HTTP {resp.status_code}"}
                except Exception as e:
                    print(f"  ERROR {key}: {e}")
                    results[key] = {"success": False, "error": str(e)}
            if not downloaded:
                print(f"  SKIP {key}: all URLs failed")

    versions["last_auto_update"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    save_versions(versions)
    load_databases_into_memory()
    return results


def needs_update() -> bool:
    from config import DB_AUTO_UPDATE_DAYS
    versions = load_versions()
    last = versions.get("last_auto_update")
    if not last:
        return True
    try:
        last_dt = datetime.strptime(last, "%Y-%m-%d %H:%M UTC")
        return datetime.utcnow() - last_dt > timedelta(days=DB_AUTO_UPDATE_DAYS)
    except:
        return True


# ── Parsers ────────────────────────────────────────────────────────────────────

def _parse_plaintext(filepath: Path) -> list:
    """Plain text — one UA string per line."""
    result = []
    for ln in filepath.read_text(encoding="utf-8", errors="ignore").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith(("#", ";", "//")):
            continue
        # Skip config directive lines but NOT short bot names
        if any(ln.startswith(x) for x in (
            "<", "}", "{", "map ", "server ", "location ",
            "BrowserMatch", "SetEnvIf", "Order ", "Allow from",
            "Deny from", "Require ", "User-agent:", "Disallow:",
            "proxy_", "error_", "access_", "return ", "rewrite "
        )):
            continue
        if ln.endswith(("{", "}", ";")):
            continue
        result.append(ln)
    return result


def _parse_conf(filepath: Path) -> list:
    """
    Parse nginx map or apache BrowserMatchNoCase conf files.
    Extracts the UA string/pattern from each rule line.

    Nginx format:  ~*"SomeBotName"  1;
    Apache format: BrowserMatchNoCase "SomeBotName" bad_bot
    Plain list:    SomeBotName  (just the name, one per line)
    """
    result = []
    # Match quoted string: ~*"value" or "value" or 'value'
    pat_quoted = re.compile(r'[~*]*["\']([^"\']{2,})["\']')
    # Match tilde+word (nginx regex): ~*SomeBotName
    pat_tilde  = re.compile(r'~[*]?([A-Za-z0-9_./ +-]{3,})')

    for ln in filepath.read_text(encoding="utf-8", errors="ignore").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith(("#", ";", "//", "$", "map ", "}")):
            continue

        # Try quoted match first
        m = pat_quoted.search(ln)
        if m:
            val = m.group(1).strip()
            if val and len(val) >= 2:
                result.append(val)
            continue

        # Try tilde match
        m2 = pat_tilde.search(ln)
        if m2:
            val = m2.group(1).strip()
            if val and len(val) >= 2:
                result.append(val)
            continue

        # Plain list line (just the bot name, no special chars)
        if re.match(r'^[A-Za-z0-9][\w\s./+\-]{1,}$', ln) and not ln.startswith(("BrowserMatch", "SetEnvIf")):
            result.append(ln)

    return list(dict.fromkeys(result))  # deduplicate


def _parse_mthcht_csv(filepath: Path) -> dict:
    result = {}
    try:
        text = filepath.read_text(encoding="utf-8", errors="ignore")
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            ua       = (row.get("http_user_agent") or "").strip()
            name     = (row.get("metadata_tool") or row.get("metadata_description") or "Unknown").strip()
            category = (row.get("metadata_category") or "Malware").strip()
            severity = (row.get("metadata_severity") or "high").strip().lower()
            if ua and len(ua) > 1:
                if severity not in ("critical", "high", "medium", "low"):
                    severity = "high"
                result[ua.lower()] = {"name": name, "category": category, "severity": severity}
    except Exception as e:
        print(f"  mthcht parse error: {e}")
    return result


def _parse_crawlers_json(filepath: Path) -> list:
    data = json.loads(filepath.read_text())
    result = []
    for item in data:
        if not isinstance(item, dict):
            continue
        for inst in item.get("instances", []):
            if isinstance(inst, str) and len(inst) > 4:
                result.append(inst.lower())
        pat = item.get("pattern", "")
        if pat and len(pat) > 4:
            result.append(pat.lower())
    return list(dict.fromkeys(result))


def _parse_matomo_yaml(filepath):
    import re as _re
    raw = filepath.read_text(encoding='utf-8', errors='ignore')
    bots = set()
    metachar = _re.compile(r'[\^$()\[\]*+?{}|]')
    for line in raw.splitlines():
        s = line.strip()
        # Both '- regex:' and '  regex:' formats
        if 'regex:' not in s:
            continue
        val = s.split('regex:', 1)[-1].strip().strip(chr(39)).strip(chr(34))
        # Strip regex metacharacters
        val = metachar.sub('', val)
        val = val.replace('.*', '').replace('(?:', '').replace('(?i)', '').strip()
        if val and len(val) > 3:
            bots.add(val.lower())
    print(f'    matomo parsed: {len(bots)} entries')
    return list(bots)



def _parse_matomo_php(filepath):
    return _parse_matomo_yaml(filepath)


def _auto_parse(key: str, filepath: Path) -> list:
    """Route to the correct parser based on source key."""
    parse_type = SOURCES[key].get("parse", "plaintext")
    if parse_type == "conf":
        return _parse_conf(filepath)
    elif parse_type == "plaintext":
        return _parse_plaintext(filepath)
    elif parse_type == "csv":
        return list(_parse_mthcht_csv(filepath).keys())
    elif parse_type == "json_crawlers":
        return _parse_crawlers_json(filepath)
    elif parse_type in ("php", "yaml"):
        return _parse_matomo_php(filepath)
    return _parse_plaintext(filepath)


# ── Load into memory ───────────────────────────────────────────────────────────
def load_databases_into_memory():
    global _bad_bots_set, _bad_bots_list, _malware_map, _crawler_list, _matomo_bots, _db_loaded
    versions = load_versions()
    all_bad  = set()

    # Bad bot sources → combined set
    for key in ("nginx_bots", "apache_bots", "seclists_ua"):
        f = SOURCES[key]["file"]
        if f.exists() and f.stat().st_size > 100:
            try:
                items = _auto_parse(key, f)
                all_bad.update(i.lower() for i in items if i.strip())
                versions[f"{key}_count"] = len(items)
                print(f"  {key}: {len(items):,}")
            except Exception as e:
                print(f"  {key} parse error: {e}")
        else:
            print(f"  {key}: not downloaded yet")

    _bad_bots_set  = all_bad
    _bad_bots_list = sorted(all_bad, key=len, reverse=True)
    versions["bad_bots_total"] = len(_bad_bots_set)
    print(f"  Bad bots combined (deduped): {len(_bad_bots_set):,}")

    # mthcht malware intel
    f = SOURCES["mthcht_malware"]["file"]
    if f.exists() and f.stat().st_size > 100:
        _malware_map = _parse_mthcht_csv(f)
        versions["mthcht_count"] = len(_malware_map)
        print(f"  mthcht_malware: {len(_malware_map):,}")
    else:
        _malware_map = {}
        print(f"  mthcht_malware: not downloaded yet")

    # Crawlers
    f = SOURCES["crawlers"]["file"]
    if f.exists() and f.stat().st_size > 100:
        try:
            _crawler_list = _parse_crawlers_json(f)
            versions["crawlers_count"] = len(_crawler_list)
            print(f"  crawlers: {len(_crawler_list):,}")
        except Exception as e:
            print(f"  crawlers error: {e}")
    else:
        print(f"  crawlers: not downloaded yet")

    # Matomo
    f = SOURCES["matomo_bots"]["file"]
    if f.exists() and f.stat().st_size > 100:
        try:
            _matomo_bots = _parse_matomo_yaml(f)
            versions["matomo_count"] = len(_matomo_bots)
            print(f"  matomo_bots: {len(_matomo_bots):,}")
        except Exception as e:
            print(f"  matomo error: {e}")
            _matomo_bots = []
    else:
        _matomo_bots = []
        print(f"  matomo_bots: not downloaded yet")

    total = len(_bad_bots_set) + len(_malware_map) + len(_crawler_list) + len(_matomo_bots)
    versions["total_patterns"] = total
    save_versions(versions)
    _db_loaded = True
    print(f"  TOTAL: {total:,} patterns in memory")


# ── Scheduler ──────────────────────────────────────────────────────────────────
def start_scheduler():
    global _scheduler
    try:
        from apscheduler.schedulers.asyncio import AsyncIOScheduler
        from config import DB_AUTO_UPDATE_DAYS
        _scheduler = AsyncIOScheduler()
        async def _do():
            print("Scheduled auto-update starting...")
            await download_databases()
        _scheduler.add_job(_do, "interval", days=DB_AUTO_UPDATE_DAYS,
                           id="db_auto_update", replace_existing=True)
        _scheduler.start()
        print(f"Auto-update scheduler: every {DB_AUTO_UPDATE_DAYS} days")
    except ImportError:
        print("APScheduler not installed")
    except Exception as e:
        print(f"Scheduler error: {e}")

def stop_scheduler():
    global _scheduler
    if _scheduler:
        try:
            _scheduler.shutdown()
        except:
            pass


# ── Status ─────────────────────────────────────────────────────────────────────
def get_db_status() -> dict:
    versions = load_versions()
    status = {}
    for key, src in SOURCES.items():
        f  = src["file"]
        ok = f.exists() and f.stat().st_size > 100
        # Use live in-memory count for mthcht/crawlers/matomo, saved count for others
        if key == "mthcht_malware":
            count = len(_malware_map) if _malware_map else versions.get("mthcht_count", 0)
        elif key == "crawlers":
            count = len(_crawler_list) if _crawler_list else versions.get("crawlers_count", 0)
        elif key == "matomo_bots":
            count = len(_matomo_bots) if _matomo_bots else versions.get("matomo_count", 0)
        else:
            count = versions.get(f"{key}_count", 0)

        status[key] = {
            "name":         src["desc"],
            "loaded":       ok,
            "last_updated": versions.get(f"{key}_updated", "Never"),
            "entry_count":  count,
        }

    status["db_loaded"]        = _db_loaded
    status["last_auto_update"] = versions.get("last_auto_update", "Never")
    status["next_update"]      = _get_next_update_time()
    total_live = len(_bad_bots_set) + len(_malware_map) + len(_crawler_list) + len(_matomo_bots)
    status["in_memory"] = {
        "bad_bots_combined": len(_bad_bots_set),
        "malware_intel":     len(_malware_map),
        "crawlers":          len(_crawler_list),
        "matomo_bots":       len(_matomo_bots),
        "total":             total_live,
    }
    return status

def _get_next_update_time() -> str:
    from config import DB_AUTO_UPDATE_DAYS
    versions = load_versions()
    last = versions.get("last_auto_update")
    if not last:
        return "On next startup"
    try:
        last_dt = datetime.strptime(last, "%Y-%m-%d %H:%M UTC")
        return (last_dt + timedelta(days=DB_AUTO_UPDATE_DAYS)).strftime("%Y-%m-%d %H:%M UTC")
    except:
        return "Unknown"

def any_database_exists() -> bool:
    return any(src["file"].exists() and src["file"].stat().st_size > 100 for src in SOURCES.values())

def check_databases_exist() -> bool:
    return all(src["file"].exists() and src["file"].stat().st_size > 100 for src in SOURCES.values())


# ── Token allowlist — fragments that appear in virtually every real browser UA ──
# Any bad-bot entry that is ONLY one of these tokens (or a subset of them) must
# never fire a partial match — it would hit every Chrome, Firefox, Safari etc.
_BROWSER_NOISE_TOKENS = {
    "mozilla", "mozilla/5.0", "mozilla/4.0",
    "applewebkit", "applewebkit/537.36", "webkit",
    "gecko", "like gecko", "khtml, like gecko",
    "chrome", "safari", "firefox", "opera", "msie", "trident",
    "windows", "windows nt", "win64", "win32", "x64", "x86_64",
    "macintosh", "mac os x", "linux", "android", "iphone", "ipad",
    "mobile", "desktop", "compatible",
    "intel mac os x", "cpu iphone os", "cpu os",
    "khtml",
}

def _is_noise_entry(entry: str) -> bool:
    """Return True if an entry is too generic to safely partial-match."""
    e = entry.strip().lower()
    # Reject if it's a known browser noise token
    if e in _BROWSER_NOISE_TOKENS:
        return True
    # Reject very short entries (< 8 chars) for partial matching — too many false hits
    if len(e) < 8:
        return True
    # Reject entries that are pure version strings like "5.0" or "537.36"
    if re.match(r'^[\d./\s]+$', e):
        return True
    # Reject entries consisting only of generic browser/OS words
    words = set(re.split(r'[\s/;()]+', e))
    if words and words.issubset(_BROWSER_NOISE_TOKENS | {'', 'like', 'the', 'and', 'or'}):
        return True
    return False


# ── Detection ──────────────────────────────────────────────────────────────────
def check_bad_bots(ua: str) -> dict:
    if not _bad_bots_set:
        return {"found": False}
    ua_lower = ua.lower()

    # Exact match — highest confidence
    if ua_lower in _bad_bots_set:
        return {"found": True, "match_type": "exact",
                "source_name": "Bad Bot Database", "score_add": 60, "severity": "critical"}

    # Partial match — ONLY for entries that are specific enough (≥ 8 chars, not noise)
    for bad in _bad_bots_list[:5000]:
        if len(bad) < 8:
            continue
        if _is_noise_entry(bad):
            continue
        if bad in ua_lower:
            return {"found": True, "match_type": "partial", "matched": bad,
                    "source_name": "Bad Bot Database", "score_add": 45, "severity": "high"}
    return {"found": False}


def check_malware_intel(ua: str) -> dict:
    if not _malware_map:
        return {"found": False}
    ua_lower = ua.lower()

    # Exact match
    if ua_lower in _malware_map:
        info = _malware_map[ua_lower]
        return {"found": True, "match_type": "exact", **info,
                "source_name": "mthcht Malware Intelligence", "score_add": 75}

    # Partial match — require ≥ 12 chars and not noise (malware UAs tend to be very specific)
    for known, info in _malware_map.items():
        if len(known) < 12:
            continue
        if _is_noise_entry(known):
            continue
        if known in ua_lower:
            return {"found": True, "match_type": "partial", **info,
                    "source_name": "mthcht Malware Intelligence", "score_add": 60}
    return {"found": False}


def check_crawlers(ua: str) -> dict:
    if not _crawler_list:
        return {"found": False}
    ua_lower = ua.lower()
    for c in _crawler_list:
        if len(c) < 8 or _is_noise_entry(c):
            continue
        if c in ua_lower:
            return {"found": True, "matched": c,
                    "source_name": "Crawler UA Database", "score_add": -20, "severity": "info"}
    return {"found": False}


def check_matomo(ua: str) -> dict:
    if not _matomo_bots:
        return {"found": False}
    ua_lower = ua.lower()
    for bot in _matomo_bots:
        if len(bot) < 8 or _is_noise_entry(bot):
            continue
        if bot in ua_lower:
            return {"found": True, "matched": bot,
                    "source_name": "Matomo Device Detector", "score_add": 30, "severity": "medium"}
    return {"found": False}

def run_db_checks(ua: str) -> dict:
    malware = check_malware_intel(ua)
    bad_bot = check_bad_bots(ua)
    crawler = check_crawlers(ua)
    matomo  = check_matomo(ua)

    db_flags = []
    db_score = 0
    sources_hit = []

    if malware.get("found"):
        db_flags.append({"type": "db_malware",
                         "label": f"Malware UA: {malware.get('name','Unknown')} [{malware.get('category','Malware')}]",
                         "severity": malware.get("severity", "critical"),
                         "category": malware.get("category", "")})
        db_score += malware["score_add"]
        sources_hit.append(malware["source_name"])

    if bad_bot.get("found") and not malware.get("found"):
        db_flags.append({"type": "db_bad_bot",
                         "label": f"Listed in {bad_bot['source_name']} ({bad_bot['match_type']} match)",
                         "severity": bad_bot["severity"]})
        db_score += bad_bot["score_add"]
        sources_hit.append(bad_bot["source_name"])

    if crawler.get("found"):
        db_flags.append({"type": "db_crawler",
                         "label": f"Known Crawler — {crawler['source_name']}",
                         "severity": "info"})
        db_score += crawler["score_add"]
        sources_hit.append(crawler["source_name"])

    if matomo.get("found") and not crawler.get("found"):
        db_flags.append({"type": "db_matomo",
                         "label": f"Bot — {matomo['source_name']}",
                         "severity": matomo["severity"]})
        db_score += matomo["score_add"]
        sources_hit.append(matomo["source_name"])

    return {
        "db_flags":       db_flags,
        "db_score":       db_score,
        "db_sources_hit": sources_hit,
        "db_loaded":      _db_loaded,
        "db_counts": {
            "bad_bots":  len(_bad_bots_set),
            "malware":   len(_malware_map),
            "crawlers":  len(_crawler_list),
            "matomo":    len(_matomo_bots),
        }
    }


# ── Init ───────────────────────────────────────────────────────────────────────
if any_database_exists():
    print("Loading existing databases from disk...")
    load_databases_into_memory()