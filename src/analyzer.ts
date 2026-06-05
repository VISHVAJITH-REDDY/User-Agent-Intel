/**
 * Layer 1 — Rule Engine
 * Port of analyzer.py to TypeScript
 */

import type { RuleEngineResult } from './types';

const AUTOMATION_KEYWORDS = [
  "headlesschrome", "phantomjs", "selenium", "playwright", "puppeteer",
  "webdriver", "htmlunit", "zombie", "slimerjs", "casperjs", "nightmare",
  "cypress", "testcafe", "watir", "pyppeteer", "mechanize", "scrapy",
  "splash", "spynner", "twill", "windmill", "webrat",
  "ghost.py", "requestshtml", "seleniumwire",
];

const SCANNER_KEYWORDS = [
  "sqlmap", "nikto", "nmap", "masscan", "zgrab", "acunetix", "nessus",
  "openvas", "dirbuster", "gobuster", "wfuzz", "burpsuite", "owasp zap",
  "arachni", "w3af", "skipfish", "havij", "vega", "metasploit",
  "hydra", "medusa", "nuclei", "ffuf", "feroxbuster", "wpscan", "joomscan",
  "dirb", "commix", "xsser", "beef", "setoolkit",
  "netsparker", "appspider", "webinspect", "qualys", "tenable",
  "invicti", "detectify", "intruder", "pentest-tools", "exploitdb",
];

const HTTP_LIB_KEYWORDS = [
  "python-requests/", "python-urllib/", "python-httpx/",
  "go-http-client/", "go http package",
  "curl/", "wget/",
  "libwww-perl", "lwp-trivialhttp", "lwp-useragent",
  "okhttp/", "apache-httpclient/", "apache-cxf/",
  "axios/", "node-fetch/", "undici/",
  "aiohttp/", "pycurl/", "urllib3/", "httpx/",
  "restsharp/", "unirest-java",
  "java-http-client", "java.net.http",
  "clj-http", "typhoeus", "excon",
  "reactor-netty/",
];

const MALWARE_KEYWORDS = [
  "lokibot", "raccoon stealer", "redline stealer",
  "azorult", "vidar stealer", "trickbot", "emotet", "dridex", "qakbot", "ursnif",
  "mirai", "gafgyt", "bashlite",
  "meterpreter", "cobaltstrike", "cobalt strike",
  "pupy", "poshc2", "covenant", "sliver", "brute ratel",
  "bunnyloader", "heartbeat_sender", "formbook", "agent tesla",
  "masslogger", "snakelogger", "hawkeye", "nanocore", "asyncrat",
  "darkcomet", "njrat", "quasar rat", "remcos", "xworm", "dcrat",
];

// Word-boundary malware patterns
const MALWARE_WORD_BOUNDARY = [
  "botnet", "c2_beacon", "cnc_beacon",
];

const CRAWLER_KEYWORDS: Record<string, string> = {
  "googlebot": "Google Search Bot",
  "bingbot": "Microsoft Bing Bot",
  "slurp": "Yahoo Bot",
  "duckduckbot": "DuckDuckGo Bot",
  "baiduspider": "Baidu Spider",
  "yandexbot": "Yandex Bot",
  "facebookexternalhit": "Facebook Crawler",
  "twitterbot": "Twitter/X Bot",
  "linkedinbot": "LinkedIn Bot",
  "applebot": "Apple Bot",
  "amazonbot": "Amazon Bot",
  "semrushbot": "SEMrush Bot",
  "ahrefsbot": "Ahrefs Bot",
  "mj12bot": "Majestic Bot",
  "dotbot": "Moz DotBot",
  "petalbot": "Huawei PetalBot",
  "bytespider": "ByteDance Spider",
  "gptbot": "OpenAI GPTBot",
  "claudebot": "Anthropic ClaudeBot",
  "ccbot": "Common Crawl Bot",
  "ia_archiver": "Internet Archive",
  "googlebot-image": "Google Image Bot",
  "googlebot-news": "Google News Bot",
  "googlebot-video": "Google Video Bot",
};

const SUSPICIOUS_PATTERNS: [RegExp, string][] = [
  [/^Mozilla\/[0-9](\s*)$/, "Truncated / incomplete UA"],
  [/^-$|^\s*$/, "Empty or placeholder UA"],
  [/[<>{}\|\\^`]/, "Contains shell/injection characters"],
  [/(\w)\1{10,}/, "Abnormal repeated character sequence"],
  [/^(test|demo|example|placeholder)$/, "Test / placeholder string"],
  [/[\x00-\x08\x0b\x0c\x0e-\x1f]/, "Contains non-printable control characters"],
  [/(union\s+select|insert\s+into|drop\s+table)/i, "Possible SQL injection in UA"],
  [/(<script|javascript:|onload=)/i, "Possible XSS attempt in UA"],
  [/\.\.\//i, "Path traversal pattern in UA"],
];

const CHROME_MIN_REALISTIC = 60;
const CHROME_MAX_REALISTIC = 200;
const FIREFOX_MIN_REALISTIC = 60;
const FIREFOX_MAX_REALISTIC = 200;

function checkImpossibleCombos(ua: string, uaLower: string): Array<{ type: string; label: string; severity: string }> {
  const flags: Array<{ type: string; label: string; severity: string }> = [];

  const chromiumEngines = ["chrome/", "chromium/", "edg/", "edge/", "opr/",
    "crios/", "fxios/", "samsungbrowser/", "yabrowser/",
    "ucbrowser/", "coastsafari/"];
  const isChromium = chromiumEngines.some(t => uaLower.includes(t));

  if (uaLower.includes("safari") && uaLower.includes("windows nt") && !isChromium) {
    flags.push({ type: "fake_combo", label: "Impossible Combo: Real Safari doesn't run on Windows", severity: "high" });
  }
  if (uaLower.includes("(iphone;") && uaLower.includes("windows nt")) {
    flags.push({ type: "fake_combo", label: "Impossible Combo: iPhone cannot run on Windows", severity: "high" });
  }
  if (uaLower.includes("(ipad;") && uaLower.includes("windows nt")) {
    flags.push({ type: "fake_combo", label: "Impossible Combo: iPad cannot run on Windows", severity: "high" });
  }
  if (uaLower.includes("linux; android") && uaLower.includes("windows nt")) {
    flags.push({ type: "fake_combo", label: "Impossible Combo: Android cannot run on Windows", severity: "high" });
  }
  if (uaLower.includes("linux; android") && uaLower.includes("macintosh")) {
    flags.push({ type: "fake_combo", label: "Impossible Combo: Android cannot run on macOS", severity: "high" });
  }
  if (/windows nt \d/.test(uaLower) && /mac os x \d/.test(uaLower)) {
    flags.push({ type: "fake_combo", label: "Impossible Combo: Cannot be both Windows and macOS", severity: "high" });
  }
  if (uaLower.includes("(iphone;") && uaLower.includes("x86_64")) {
    flags.push({ type: "fake_combo", label: "Impossible Combo: iPhone cannot have x86_64 architecture", severity: "high" });
  }
  if (uaLower.includes("(x11; cros") && uaLower.includes("windows nt")) {
    flags.push({ type: "fake_combo", label: "Impossible Combo: ChromeOS and Windows are mutually exclusive", severity: "high" });
  }

  return flags;
}

function checkUAConsistency(ua: string): Array<{ type: string; label: string; severity: string }> {
  const flags: Array<{ type: string; label: string; severity: string }> = [];
  const uaLower = ua.toLowerCase();

  const isChrome = /chrome\/[\d]+/i.test(ua) && !uaLower.includes("chromium");
  const isEdge = /edg[e]?\/[\d]+/i.test(ua);
  const isOpera = /opr\/[\d]+/i.test(ua);
  const isFirefox = /firefox\/[\d]+/i.test(ua);
  const isSafariPure = /version\/[\d]+.*safari\//i.test(ua) && !isChrome && !isEdge && !isOpera;
  const isChromium = isChrome || isEdge || isOpera;

  // 1 — Chromium WebKit must be 537.36
  if (isChromium) {
    const m = ua.match(/applewebkit\/([\d.]+)/i);
    if (m && m[1] !== "537.36") {
      flags.push({ type: "spoofed", severity: "high", label: `Spoofed WebKit version: ${m[1]} — Chromium always uses 537.36` });
    }
  }

  // 2 — Chromium trailing Safari token must be 537.36
  if (isChromium) {
    const m = ua.trim().match(/safari\/([\d.]+)\s*$/i);
    if (m && m[1] !== "537.36") {
      flags.push({ type: "spoofed", severity: "high", label: `Spoofed Safari token: ${m[1]} — Chromium always uses 537.36` });
    }
  }

  // 3 — Chrome version plausibility
  if (isChrome && !isEdge && !isOpera) {
    const m = ua.match(/chrome\/([\d]+)/i);
    if (m) {
      const v = parseInt(m[1]);
      if (v < CHROME_MIN_REALISTIC) {
        flags.push({ type: "spoofed", severity: "high", label: `Implausible Chrome version: ${v} (too old for 2025)` });
      } else if (v > CHROME_MAX_REALISTIC) {
        flags.push({ type: "spoofed", severity: "high", label: `Implausible Chrome version: ${v} (does not exist yet)` });
      }
    }
  }

  // 4 — Firefox Gecko date must be 20100101
  if (isFirefox) {
    const m = ua.match(/gecko\/([\d]+)/i);
    if (m && m[1] !== "20100101") {
      flags.push({ type: "spoofed", severity: "high", label: `Spoofed Gecko date: ${m[1]} — Firefox always uses 20100101` });
    }
  }

  // 5 — Firefox version plausibility
  if (isFirefox) {
    const m = ua.match(/firefox\/([\d]+)/i);
    if (m) {
      const v = parseInt(m[1]);
      if (v < FIREFOX_MIN_REALISTIC) {
        flags.push({ type: "spoofed", severity: "high", label: `Implausible Firefox version: ${v} (too old for 2025)` });
      } else if (v > FIREFOX_MAX_REALISTIC) {
        flags.push({ type: "spoofed", severity: "high", label: `Implausible Firefox version: ${v} (does not exist yet)` });
      }
    }
  }

  // 6 — Cannot be both Chrome AND Firefox
  if (isChrome && isFirefox) {
    flags.push({ type: "spoofed", severity: "critical", label: "Impossible: UA claims to be both Chrome and Firefox" });
  }

  // 7 — Pure Safari only on Apple OS
  if (isSafariPure && !/(macintosh|iphone|ipad|mac os x)/i.test(uaLower)) {
    flags.push({ type: "spoofed", severity: "high", label: "Impossible: Pure Safari on non-Apple OS" });
  }

  // 8 — Real browsers always start with Mozilla/5.0
  if ((isChromium || isFirefox || isSafariPure) && !ua.startsWith("Mozilla/5.0")) {
    flags.push({ type: "spoofed", severity: "medium", label: "Missing Mozilla/5.0 prefix — all real browsers include this" });
  }

  return flags;
}

export function parseUA(ua: string): Record<string, string> {
  const r: Record<string, string> = {
    browser: "Unknown", browser_version: "", os: "Unknown",
    os_version: "", device: "Desktop", engine: "Unknown", raw: ua
  };

  if (/HeadlessChrome/i.test(ua)) {
    r.browser = "Headless Chrome";
    const m = ua.match(/HeadlessChrome\/([\d.]+)/i);
    if (m) r.browser_version = m[1];
  } else if (/Edg[e]?\/[\d.]+/.test(ua)) {
    r.browser = "Edge";
    const m = ua.match(/Edg[e]?\/([\d.]+)/);
    if (m) r.browser_version = m[1];
  } else if (/OPR\/|Opera/.test(ua)) {
    r.browser = "Opera";
    const m = ua.match(/OPR\/([\d.]+)/);
    if (m) r.browser_version = m[1];
  } else if (/SamsungBrowser\/([\d.]+)/.test(ua)) {
    r.browser = "Samsung Browser";
    const m = ua.match(/SamsungBrowser\/([\d.]+)/);
    if (m) r.browser_version = m[1];
  } else if (/Chrome\/([\d.]+)/.test(ua) && !ua.includes("Chromium")) {
    r.browser = "Chrome";
    const m = ua.match(/Chrome\/([\d.]+)/);
    if (m) r.browser_version = m[1];
  } else if (/Firefox\/([\d.]+)/.test(ua)) {
    r.browser = "Firefox";
    const m = ua.match(/Firefox\/([\d.]+)/);
    if (m) r.browser_version = m[1];
  } else if (/Safari\//.test(ua) && !ua.includes("Chrome")) {
    r.browser = "Safari";
    const m = ua.match(/Version\/([\d.]+)/);
    if (m) r.browser_version = m[1];
  } else if (/curl\//i.test(ua)) {
    r.browser = "curl";
    const m = ua.match(/curl\/([\d.]+)/i);
    if (m) r.browser_version = m[1];
  } else if (/python-requests/i.test(ua)) {
    r.browser = "Python Requests";
  } else if (/Go-http-client/i.test(ua)) {
    r.browser = "Go HTTP Client";
  } else if (/wget/i.test(ua)) {
    r.browser = "Wget";
  }

  if (/Windows NT 10/.test(ua)) { r.os = "Windows"; r.os_version = "10/11"; }
  else if (/Windows NT 6\.3/.test(ua)) { r.os = "Windows"; r.os_version = "8.1"; }
  else if (/Windows NT 6\.1/.test(ua)) { r.os = "Windows"; r.os_version = "7"; }
  else if (/Windows NT 5/.test(ua)) { r.os = "Windows"; r.os_version = "XP"; }
  else if (/Windows/.test(ua)) { r.os = "Windows"; }
  else if (/Macintosh|Mac OS X/.test(ua)) {
    r.os = "macOS";
    const m = ua.match(/Mac OS X ([\d_]+)/);
    if (m) r.os_version = m[1].replace(/_/g, ".");
  } else if (/Android ([\d.]+)/.test(ua)) {
    r.os = "Android";
    const m = ua.match(/Android ([\d.]+)/);
    if (m) r.os_version = m[1];
  } else if (/iPhone|iPad|iOS/.test(ua)) {
    r.os = "iOS";
    const m = ua.match(/OS ([\d_]+)/);
    if (m) r.os_version = m[1].replace(/_/g, ".");
  } else if (/CrOS/.test(ua)) {
    r.os = "ChromeOS";
  } else if (/Linux/.test(ua)) {
    r.os = "Linux";
  }

  if (/iPhone/.test(ua)) r.device = "iPhone";
  else if (/iPad/.test(ua)) r.device = "iPad";
  else if (/Android.*Mobile/.test(ua)) r.device = "Android Phone";
  else if (/Android/.test(ua)) r.device = "Android Tablet";
  else if (/Mobile/.test(ua)) r.device = "Mobile";
  else r.device = "Desktop";

  if (/AppleWebKit/.test(ua)) r.engine = "WebKit/Blink";
  else if (/Gecko/.test(ua) && !ua.includes("WebKit")) r.engine = "Gecko";
  else if (/Trident/.test(ua)) r.engine = "Trident";
  else if (/Presto/.test(ua)) r.engine = "Presto";

  return r;
}

export function analyzeRuleEngine(ua: string): RuleEngineResult & { parsed: Record<string, string>; crawler: string | null } {
  const uaLower = ua.toLowerCase();
  const flags: Array<{ type: string; label: string; severity: string }> = [];
  let score = 0;

  const parsed = parseUA(ua);

  // 1. Known legitimate crawler
  let crawlerName: string | null = null;
  for (const [kw, name] of Object.entries(CRAWLER_KEYWORDS)) {
    if (uaLower.includes(kw)) {
      crawlerName = name;
      flags.push({ type: "crawler", label: `Known Crawler: ${name}`, severity: "info" });
      score -= 30;
      break;
    }
  }

  // 2. Malware keywords
  for (const kw of MALWARE_KEYWORDS) {
    if (uaLower.includes(kw)) {
      flags.push({ type: "malware", label: `Known Malware UA Pattern: ${kw.split(' ').map(w => w[0].toUpperCase() + w.slice(1)).join(' ')}`, severity: "critical" });
      score += 70;
      break;
    }
  }

  // Malware word-boundary patterns
  if (flags.filter(f => f.type === "malware").length === 0) {
    for (const kw of MALWARE_WORD_BOUNDARY) {
      const re = new RegExp(`\\b${kw}\\b`, 'i');
      if (re.test(uaLower)) {
        flags.push({ type: "malware", label: `Known Malware UA Pattern: ${kw.charAt(0).toUpperCase() + kw.slice(1)}`, severity: "critical" });
        score += 70;
        break;
      }
    }
  }

  // 3. Automation frameworks
  for (const kw of AUTOMATION_KEYWORDS) {
    if (uaLower.includes(kw)) {
      flags.push({ type: "automation", label: `Automation Framework Detected: ${kw.charAt(0).toUpperCase() + kw.slice(1)}`, severity: "high" });
      score += 45;
      break;
    }
  }

  // 4. Security scanners
  for (const kw of SCANNER_KEYWORDS) {
    if (uaLower.includes(kw)) {
      flags.push({ type: "scanner", label: `Security Scanner Detected: ${kw.charAt(0).toUpperCase() + kw.slice(1)}`, severity: "critical" });
      score += 55;
      break;
    }
  }

  // 5. Raw HTTP libraries
  for (const kw of HTTP_LIB_KEYWORDS) {
    if (uaLower.includes(kw)) {
      flags.push({ type: "http_lib", label: `Raw HTTP Library: ${kw.replace(/\/$/, '')}`, severity: "medium" });
      score += 25;
      break;
    }
  }

  // 6. Impossible OS/device combos
  const comboFlags = checkImpossibleCombos(ua, uaLower);
  for (const f of comboFlags) {
    flags.push(f);
    score += 35;
  }

  // 7. Suspicious patterns
  for (const [pattern, reason] of SUSPICIOUS_PATTERNS) {
    if (pattern.test(uaLower)) {
      flags.push({ type: "suspicious", label: `Suspicious Pattern: ${reason}`, severity: "medium" });
      score += 20;
      break;
    }
  }

  // 8. Very short UA
  if (ua.trim().length < 15 && !crawlerName) {
    flags.push({ type: "suspicious", label: "Unusually short User-Agent string", severity: "medium" });
    score += 20;
  }

  // 9. UA internal consistency (skip for known crawlers)
  if (!crawlerName) {
    const consistencyFlags = checkUAConsistency(ua);
    for (const f of consistencyFlags) {
      flags.push(f);
      const severityMap: Record<string, number> = { critical: 40, high: 25, medium: 15 };
      score += severityMap[f.severity] ?? 15;
    }
  }

  score = Math.max(0, Math.min(100, score));

  return {
    score,
    flags,
    parsed,
    crawler: crawlerName,
  };
}
