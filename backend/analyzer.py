"""
Layer 1 — Rule Engine
Fast keyword + regex detection. Zero network calls. Instant results.
"""
import re

# ── Keyword Lists ──────────────────────────────────────────────────────────────

AUTOMATION_KEYWORDS = [
    "headlesschrome","phantomjs","selenium","playwright","puppeteer",
    "webdriver","htmlunit","zombie","slimerjs","casperjs","nightmare",
    "cypress","testcafe","watir","pyppeteer","mechanize","scrapy",
    "splash","spynner","twill","windmill","webrat",
    "ghost.py","requestshtml","seleniumwire",
]

SCANNER_KEYWORDS = [
    "sqlmap","nikto","nmap","masscan","zgrab","acunetix","nessus",
    "openvas","dirbuster","gobuster","wfuzz","burpsuite","owasp zap",
    "arachni","w3af","skipfish","havij","vega","metasploit",
    "hydra","medusa","nuclei","ffuf","feroxbuster","wpscan","joomscan",
    "dirb","commix","xsser","beef","setoolkit",
    "netsparker","appspider","webinspect","qualys","tenable",
    "invicti","detectify","intruder","pentest-tools","exploitdb",
]

HTTP_LIB_KEYWORDS = [
    # Unambiguous — these ONLY appear in HTTP library UAs, never real browsers
    "python-requests/","python-urllib/","python-httpx/",
    "go-http-client/","go http package",
    "curl/","wget/",
    "libwww-perl","lwp-trivialhttp","lwp-useragent",
    "okhttp/","apache-httpclient/","apache-cxf/",
    "axios/","node-fetch/","undici/",
    "aiohttp/","pycurl/","urllib3/","httpx/",
    "restsharp/","unirest-java",
    "java-http-client","java.net.http",
    "clj-http","typhoeus","excon",
    "reactor-netty/",
]

MALWARE_KEYWORDS = [
    "lokibot","raccoon stealer","redline stealer",
    "azorult","vidar stealer","trickbot","emotet","dridex","qakbot","ursnif",
    "mirai","gafgyt","bashlite",
    "meterpreter","cobaltstrike","cobalt strike",
    "pupy","poshc2","covenant","sliver","brute ratel",
    "bunnyloader","heartbeat_sender","formbook","agent tesla",
    "masslogger","snakelogger","hawkeye","nanocore","asyncrat",
    "darkcomet","njrat","quasar rat","remcos","xworm","dcrat",
    # Generic botnet/c2 markers (short words — require word boundaries)
    r"\bbotnet\b", r"\bc2_beacon\b", r"\bcnc_beacon\b",
]

CRAWLER_KEYWORDS = {
    "googlebot":          "Google Search Bot",
    "bingbot":            "Microsoft Bing Bot",
    "slurp":              "Yahoo Bot",
    "duckduckbot":        "DuckDuckGo Bot",
    "baiduspider":        "Baidu Spider",
    "yandexbot":          "Yandex Bot",
    "facebookexternalhit":"Facebook Crawler",
    "twitterbot":         "Twitter/X Bot",
    "linkedinbot":        "LinkedIn Bot",
    "applebot":           "Apple Bot",
    "amazonbot":          "Amazon Bot",
    "semrushbot":         "SEMrush Bot",
    "ahrefsbot":          "Ahrefs Bot",
    "mj12bot":            "Majestic Bot",
    "dotbot":             "Moz DotBot",
    "petalbot":           "Huawei PetalBot",
    "bytespider":         "ByteDance Spider",
    "gptbot":             "OpenAI GPTBot",
    "claudebot":          "Anthropic ClaudeBot",
    "ccbot":              "Common Crawl Bot",
    "ia_archiver":        "Internet Archive",
    "googlebot-image":    "Google Image Bot",
    "googlebot-news":     "Google News Bot",
    "googlebot-video":    "Google Video Bot",
}

SUSPICIOUS_PATTERNS = [
    (r"^Mozilla/[0-9](\s*)$",            "Truncated / incomplete UA"),
    (r"^-$|^\s*$",                        "Empty or placeholder UA"),
    (r"[<>{}\|\\^`]",                     "Contains shell/injection characters"),
    (r"(\w)\1{10,}",                      "Abnormal repeated character sequence"),
    (r"^(test|demo|example|placeholder)$","Test / placeholder string"),
    (r"[\x00-\x08\x0b\x0c\x0e-\x1f]",   "Contains non-printable control characters"),
    (r"(union\s+select|insert\s+into|drop\s+table)", "Possible SQL injection in UA"),
    (r"(<script|javascript:|onload=)",    "Possible XSS attempt in UA"),
    (r"\.\./|\.\.\\",                     "Path traversal pattern in UA"),
]


# ── Impossible combo checker (function-based, no regex lookahead bugs) ─────────
def check_impossible_combos(ua: str, ua_lower: str) -> list:
    """
    Returns list of flag dicts for impossible OS/browser combinations.
    Uses direct string checks — avoids regex lookahead false positives.
    """
    flags = []

    # Tokens that indicate a real Chromium-based engine
    # All of these legitimately include "Safari/NNN" in their UA
    chromium_engines = ["chrome/", "chromium/", "edg/", "edge/", "opr/",
                        "crios/", "fxios/", "samsungbrowser/", "yabrowser/",
                        "ucbrowser/", "coastsafari/"]
    is_chromium = any(t in ua_lower for t in chromium_engines)

    # ── Safari on Windows (only flag if NOT a Chromium browser) ──────────────
    # Chrome/Edge/Opera on Windows always contains "Safari/NNN" — that's normal
    if "safari" in ua_lower and "windows nt" in ua_lower and not is_chromium:
        flags.append({
            "type": "fake_combo",
            "label": "Impossible Combo: Real Safari doesn't run on Windows",
            "severity": "high"
        })

    # ── iPhone/iPad on Windows ────────────────────────────────────────────────
    if "(iphone;" in ua_lower and "windows nt" in ua_lower:
        flags.append({
            "type": "fake_combo",
            "label": "Impossible Combo: iPhone cannot run on Windows",
            "severity": "high"
        })
    if "(ipad;" in ua_lower and "windows nt" in ua_lower:
        flags.append({
            "type": "fake_combo",
            "label": "Impossible Combo: iPad cannot run on Windows",
            "severity": "high"
        })

    # ── Android on Windows or macOS ───────────────────────────────────────────
    if "linux; android" in ua_lower and "windows nt" in ua_lower:
        flags.append({
            "type": "fake_combo",
            "label": "Impossible Combo: Android cannot run on Windows",
            "severity": "high"
        })
    if "linux; android" in ua_lower and "macintosh" in ua_lower:
        flags.append({
            "type": "fake_combo",
            "label": "Impossible Combo: Android cannot run on macOS",
            "severity": "high"
        })

    # ── Both Windows and macOS in OS section ─────────────────────────────────
    if re.search(r"windows nt \d", ua_lower) and re.search(r"mac os x \d", ua_lower):
        flags.append({
            "type": "fake_combo",
            "label": "Impossible Combo: Cannot be both Windows and macOS",
            "severity": "high"
        })

    # ── iPhone with x86_64 (iPhones are ARM only) ────────────────────────────
    if "(iphone;" in ua_lower and "x86_64" in ua_lower:
        flags.append({
            "type": "fake_combo",
            "label": "Impossible Combo: iPhone cannot have x86_64 architecture",
            "severity": "high"
        })

    # ── ChromeOS + Windows ────────────────────────────────────────────────────
    if "(x11; cros" in ua_lower and "windows nt" in ua_lower:
        flags.append({
            "type": "fake_combo",
            "label": "Impossible Combo: ChromeOS and Windows are mutually exclusive",
            "severity": "high"
        })

    return flags


# ── Parser ─────────────────────────────────────────────────────────────────────
def parse_ua(ua: str) -> dict:
    r = {"browser":"Unknown","browser_version":"","os":"Unknown",
         "os_version":"","device":"Desktop","engine":"Unknown","raw":ua}

    if re.search(r"HeadlessChrome", ua, re.I):
        r["browser"] = "Headless Chrome"
        m = re.search(r"HeadlessChrome/([\d.]+)", ua, re.I)
        if m: r["browser_version"] = m.group(1)
    elif re.search(r"Edg[e]?/[\d.]+", ua):
        r["browser"] = "Edge"
        m = re.search(r"Edg[e]?/([\d.]+)", ua)
        if m: r["browser_version"] = m.group(1)
    elif re.search(r"OPR/|Opera", ua):
        r["browser"] = "Opera"
        m = re.search(r"OPR/([\d.]+)", ua)
        if m: r["browser_version"] = m.group(1)
    elif re.search(r"SamsungBrowser/([\d.]+)", ua):
        r["browser"] = "Samsung Browser"
        m = re.search(r"SamsungBrowser/([\d.]+)", ua)
        if m: r["browser_version"] = m.group(1)
    elif re.search(r"Chrome/([\d.]+)", ua) and "Chromium" not in ua:
        r["browser"] = "Chrome"
        m = re.search(r"Chrome/([\d.]+)", ua)
        if m: r["browser_version"] = m.group(1)
    elif re.search(r"Firefox/([\d.]+)", ua):
        r["browser"] = "Firefox"
        m = re.search(r"Firefox/([\d.]+)", ua)
        if m: r["browser_version"] = m.group(1)
    elif re.search(r"Safari/", ua) and "Chrome" not in ua:
        r["browser"] = "Safari"
        m = re.search(r"Version/([\d.]+)", ua)
        if m: r["browser_version"] = m.group(1)
    elif re.search(r"curl/", ua, re.I):
        r["browser"] = "curl"
        m = re.search(r"curl/([\d.]+)", ua, re.I)
        if m: r["browser_version"] = m.group(1)
    elif re.search(r"python-requests", ua, re.I):
        r["browser"] = "Python Requests"
    elif re.search(r"Go-http-client", ua, re.I):
        r["browser"] = "Go HTTP Client"
    elif re.search(r"wget", ua, re.I):
        r["browser"] = "Wget"

    if re.search(r"Windows NT 10", ua):
        r["os"] = "Windows"; r["os_version"] = "10/11"
    elif re.search(r"Windows NT 6\.3", ua):
        r["os"] = "Windows"; r["os_version"] = "8.1"
    elif re.search(r"Windows NT 6\.1", ua):
        r["os"] = "Windows"; r["os_version"] = "7"
    elif re.search(r"Windows NT 5", ua):
        r["os"] = "Windows"; r["os_version"] = "XP"
    elif re.search(r"Windows", ua):
        r["os"] = "Windows"
    elif re.search(r"Macintosh|Mac OS X", ua):
        r["os"] = "macOS"
        m = re.search(r"Mac OS X ([\d_]+)", ua)
        if m: r["os_version"] = m.group(1).replace("_",".")
    elif re.search(r"Android ([\d.]+)", ua):
        r["os"] = "Android"
        m = re.search(r"Android ([\d.]+)", ua)
        if m: r["os_version"] = m.group(1)
    elif re.search(r"iPhone|iPad|iOS", ua):
        r["os"] = "iOS"
        m = re.search(r"OS ([\d_]+)", ua)
        if m: r["os_version"] = m.group(1).replace("_",".")
    elif re.search(r"CrOS", ua):
        r["os"] = "ChromeOS"
    elif re.search(r"Linux", ua):
        r["os"] = "Linux"

    if re.search(r"iPhone", ua):            r["device"] = "iPhone"
    elif re.search(r"iPad", ua):            r["device"] = "iPad"
    elif re.search(r"Android.*Mobile", ua): r["device"] = "Android Phone"
    elif re.search(r"Android", ua):         r["device"] = "Android Tablet"
    elif re.search(r"Mobile", ua):          r["device"] = "Mobile"
    else:                                   r["device"] = "Desktop"

    if re.search(r"AppleWebKit", ua):                       r["engine"] = "WebKit/Blink"
    elif re.search(r"Gecko", ua) and "WebKit" not in ua:    r["engine"] = "Gecko"
    elif re.search(r"Trident", ua):                         r["engine"] = "Trident"
    elif re.search(r"Presto", ua):                          r["engine"] = "Presto"

    return r


# ── Analyzer ───────────────────────────────────────────────────────────────────
def analyze_ua(ua: str) -> dict:
    ua_lower = ua.lower()
    flags = []
    score = 0

    parsed = parse_ua(ua)

    # 1. Known legitimate crawler (reduces score, skip further heavy checks)
    crawler_name = None
    for kw, name in CRAWLER_KEYWORDS.items():
        if kw in ua_lower:
            crawler_name = name
            flags.append({"type":"crawler","label":f"Known Crawler: {name}","severity":"info"})
            score -= 30
            break

    # 2. Malware keyword
    for kw in MALWARE_KEYWORDS:
        if kw.startswith(r"\b"):
            # word-boundary pattern
            if re.search(kw, ua_lower):
                clean_kw = kw.replace(r"\b", "").title()
                flags.append({"type":"malware","label":f"Known Malware UA Pattern: {clean_kw}","severity":"critical"})
                score += 70
                break
        elif kw in ua_lower:
            flags.append({"type":"malware","label":f"Known Malware UA Pattern: {kw.title()}","severity":"critical"})
            score += 70
            break

    # 3. Automation framework
    for kw in AUTOMATION_KEYWORDS:
        if kw in ua_lower:
            flags.append({"type":"automation","label":f"Automation Framework Detected: {kw.title()}","severity":"high"})
            score += 45
            break

    # 4. Security scanner
    for kw in SCANNER_KEYWORDS:
        if kw in ua_lower:
            flags.append({"type":"scanner","label":f"Security Scanner Detected: {kw.title()}","severity":"critical"})
            score += 55
            break

    # 5. Raw HTTP library
    for kw in HTTP_LIB_KEYWORDS:
        if kw in ua_lower:
            flags.append({"type":"http_lib","label":f"Raw HTTP Library: {kw.rstrip('/')}","severity":"medium"})
            score += 25
            break

    # 6. Impossible OS/device combos (function-based — no regex lookahead bugs)
    combo_flags = check_impossible_combos(ua, ua_lower)
    for f in combo_flags:
        flags.append(f)
        score += 35

    # 7. Suspicious patterns
    for pattern, reason in SUSPICIOUS_PATTERNS:
        if re.search(pattern, ua_lower):
            flags.append({"type":"suspicious","label":f"Suspicious Pattern: {reason}","severity":"medium"})
            score += 20
            break  # one suspicious flag at a time

    # 8. Very short UA
    if len(ua.strip()) < 15 and not crawler_name:
        flags.append({"type":"suspicious","label":"Unusually short User-Agent string","severity":"medium"})
        score += 20

    # 9. Level 1 — UA internal consistency checks
    if not crawler_name:
        for f in check_ua_consistency(ua):
            flags.append(f)
            score += {"critical":40,"high":25,"medium":15}.get(f.get("severity","medium"),15)

    score = max(0, min(100, score))

    if score <= 20:   verdict, color = "Legitimate",       "green"
    elif score <= 50: verdict, color = "Suspicious",       "yellow"
    elif score <= 75: verdict, color = "Likely Malicious", "orange"
    else:             verdict, color = "Malicious",        "red"

    return {
        "parsed":           parsed,
        "flags":            flags,
        "risk_score":       score,
        "verdict":          verdict,
        "verdict_color":    color,
        "crawler":          crawler_name,
        "flag_count":       len(flags),
    }


# ── Level 1 — UA Internal Consistency Checker ─────────────────────────────────
CHROME_MIN_REALISTIC  = 60
CHROME_MAX_REALISTIC  = 200
FIREFOX_MIN_REALISTIC = 60
FIREFOX_MAX_REALISTIC = 200

def check_ua_consistency(ua: str) -> list:
    flags = []
    ua_lower = ua.lower()

    is_chrome   = bool(re.search(r"chrome/[\d]+", ua, re.I)) and "chromium" not in ua_lower
    is_edge     = bool(re.search(r"edg[e]?/[\d]+", ua, re.I))
    is_opera    = bool(re.search(r"opr/[\d]+", ua, re.I))
    is_firefox  = bool(re.search(r"firefox/[\d]+", ua, re.I))
    is_safari_p = bool(re.search(r"version/[\d]+.*safari/", ua, re.I)) and not is_chrome and not is_edge and not is_opera
    is_chromium = is_chrome or is_edge or is_opera

    # 1 — Chromium WebKit must be 537.36
    if is_chromium:
        m = re.search(r"applewebkit/([\d.]+)", ua, re.I)
        if m and m.group(1) != "537.36":
            flags.append({"type":"spoofed","severity":"high",
                "label":f"Spoofed WebKit version: {m.group(1)} — Chromium always uses 537.36"})

    # 2 — Chromium trailing Safari token must be 537.36
    if is_chromium:
        m = re.search(r"safari/([\d.]+)\s*$", ua.strip(), re.I)
        if m and m.group(1) != "537.36":
            flags.append({"type":"spoofed","severity":"high",
                "label":f"Spoofed Safari token: {m.group(1)} — Chromium always uses 537.36"})

    # 3 — Chrome version plausibility
    if is_chrome and not is_edge and not is_opera:
        m = re.search(r"chrome/([\d]+)", ua, re.I)
        if m:
            v = int(m.group(1))
            if v < CHROME_MIN_REALISTIC:
                flags.append({"type":"spoofed","severity":"high",
                    "label":f"Implausible Chrome version: {v} (too old for 2025)"})
            elif v > CHROME_MAX_REALISTIC:
                flags.append({"type":"spoofed","severity":"high",
                    "label":f"Implausible Chrome version: {v} (does not exist yet)"})

    # 4 — Firefox Gecko date must be 20100101
    if is_firefox:
        m = re.search(r"gecko/([\d]+)", ua, re.I)
        if m and m.group(1) != "20100101":
            flags.append({"type":"spoofed","severity":"high",
                "label":f"Spoofed Gecko date: {m.group(1)} — Firefox always uses 20100101"})

    # 5 — Firefox version plausibility
    if is_firefox:
        m = re.search(r"firefox/([\d]+)", ua, re.I)
        if m:
            v = int(m.group(1))
            if v < FIREFOX_MIN_REALISTIC:
                flags.append({"type":"spoofed","severity":"high",
                    "label":f"Implausible Firefox version: {v} (too old for 2025)"})
            elif v > FIREFOX_MAX_REALISTIC:
                flags.append({"type":"spoofed","severity":"high",
                    "label":f"Implausible Firefox version: {v} (does not exist yet)"})

    # 6 — Cannot be both Chrome AND Firefox
    if is_chrome and is_firefox:
        flags.append({"type":"spoofed","severity":"critical",
            "label":"Impossible: UA claims to be both Chrome and Firefox"})

    # 7 — Pure Safari only on Apple OS
    if is_safari_p and not re.search(r"(macintosh|iphone|ipad|mac os x)", ua_lower):
        flags.append({"type":"spoofed","severity":"high",
            "label":"Impossible: Pure Safari on non-Apple OS"})

    # 8 — Real browsers always start with Mozilla/5.0
    if (is_chromium or is_firefox or is_safari_p) and not ua.startswith("Mozilla/5.0"):
        flags.append({"type":"spoofed","severity":"medium",
            "label":"Missing Mozilla/5.0 prefix — all real browsers include this"})

    return flags