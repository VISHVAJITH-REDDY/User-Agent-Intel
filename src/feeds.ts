/**
 * Threat-feed refresher — runtime port of db_engine.py download + parse logic.
 *
 * The Worker ships with a bundled snapshot of the threat data (src/data/*.ts) so
 * it always works on a cold deploy. This module fetches fresh copies of the six
 * upstream feeds on a weekly cron (or on-demand via POST /db-update), parses them
 * with the same rules as the original Python engine, and caches the result in KV.
 * The analyze path prefers the KV copy and falls back to the bundle.
 */

import type { Env, ThreatData } from './types';
import type { MalwareEntry } from './data/malware';

// ── Sources (mirrors SOURCES in db_engine.py) ────────────────────────────────
type ParseType = 'plaintext' | 'csv' | 'json_crawlers' | 'yaml';

interface Source {
  key: string;
  urls: string[]; // primary + optional fallback
  desc: string;
  parse: ParseType;
}

const SOURCES: Source[] = [
  {
    key: 'nginx_bots',
    // The maintainer's canonical plaintext generator list — clean one-name-per-line.
    // (The bots.d/*.conf form is now mostly uncombable regex fragments.)
    urls: [
      'https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list',
      'https://raw.githubusercontent.com/mitchellkrogza/apache-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list',
    ],
    desc: 'Nginx Bad Bot Blocker',
    parse: 'plaintext',
  },
  {
    key: 'apache_bots',
    urls: [
      'https://raw.githubusercontent.com/mitchellkrogza/apache-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list',
      'https://raw.githubusercontent.com/mitchellkrogza/apache-ultimate-bad-bot-blocker/master/bots.d/blacklist-user-agents.conf',
    ],
    desc: 'Apache Bad Bot Blocker',
    parse: 'plaintext',
  },
  {
    key: 'seclists_ua',
    urls: [
      'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/User-Agents/UserAgents.fuzz.txt',
      'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Miscellaneous/User-Agents/user_agents.txt',
    ],
    desc: 'SecLists UA Database',
    parse: 'plaintext',
  },
  {
    key: 'mthcht_malware',
    urls: ['https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/suspicious_http_user_agents_list.csv'],
    desc: 'mthcht Malware UA Intelligence',
    parse: 'csv',
  },
  {
    key: 'crawlers',
    urls: ['https://raw.githubusercontent.com/monperrus/crawler-user-agents/master/crawler-user-agents.json'],
    desc: 'Crawler UA Database',
    parse: 'json_crawlers',
  },
  {
    key: 'matomo_bots',
    urls: [
      'https://raw.githubusercontent.com/matomo-org/device-detector/master/regexes/bots.yml',
      'https://raw.githubusercontent.com/matomo-org/device-detector/master/Tests/fixtures/bots.yml',
    ],
    desc: 'Matomo Device Detector',
    parse: 'yaml',
  },
];

// KV keys
const KV_BAD_BOTS = 'feed:bad_bots';
const KV_MALWARE = 'feed:malware';
const KV_CRAWLERS = 'feed:crawlers';
const KV_MATOMO = 'feed:matomo';
const KV_META = 'feed:meta';

export interface FeedMeta {
  last_update: string;
  sources: Record<string, { name: string; ok: boolean; count: number; updated: string }>;
  counts: { bad_bots: number; malware: number; crawlers: number; matomo: number };
}

// ── Parsers (faithful ports of db_engine.py) ─────────────────────────────────

function parsePlaintext(text: string): string[] {
  const result: string[] = [];
  const skipPrefixes = [
    '<', '}', '{', 'map ', 'server ', 'location ',
    'BrowserMatch', 'SetEnvIf', 'Order ', 'Allow from',
    'Deny from', 'Require ', 'User-agent:', 'Disallow:',
    'proxy_', 'error_', 'access_', 'return ', 'rewrite ',
  ];
  for (const raw of text.split('\n')) {
    const ln = raw.trim();
    if (!ln || ln.startsWith('#') || ln.startsWith(';') || ln.startsWith('//')) continue;
    if (skipPrefixes.some((p) => ln.startsWith(p))) continue;
    if (ln.endsWith('{') || ln.endsWith('}') || ln.endsWith(';')) continue;
    result.push(ln);
  }
  return result;
}

/** Minimal RFC-4180-ish CSV row splitter (handles quoted fields + escaped quotes). */
function parseCSVRows(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      row.push(field);
      field = '';
    } else if (ch === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else if (ch !== '\r') {
      field += ch;
    }
  }
  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

function parseMthchtCSV(text: string): MalwareEntry[] {
  const rows = parseCSVRows(text);
  if (rows.length < 2) return [];
  const header = rows[0].map((h) => h.trim());
  const idx = (name: string) => header.indexOf(name);
  const iUA = idx('http_user_agent');
  const iTool = idx('metadata_tool');
  const iDesc = idx('metadata_description');
  const iCat = idx('metadata_category');
  const iSev = idx('metadata_severity');

  const seen = new Set<string>();
  const out: MalwareEntry[] = [];
  for (let r = 1; r < rows.length; r++) {
    const row = rows[r];
    const ua = (iUA >= 0 ? row[iUA] || '' : '').trim();
    if (!ua || ua.length <= 1) continue;
    const key = ua.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);

    const name =
      ((iTool >= 0 && row[iTool]) || (iDesc >= 0 && row[iDesc]) || 'Unknown').toString().trim() || 'Unknown';
    const category = ((iCat >= 0 && row[iCat]) || 'Malware').toString().trim() || 'Malware';
    let severity = ((iSev >= 0 && row[iSev]) || 'high').toString().trim().toLowerCase();
    if (!['critical', 'high', 'medium', 'low'].includes(severity)) severity = 'high';

    out.push({ ua, name, category, severity });
  }
  return out;
}

function parseCrawlersJson(text: string): string[] {
  const data = JSON.parse(text);
  const result: string[] = [];
  if (!Array.isArray(data)) return result;
  for (const item of data) {
    if (typeof item !== 'object' || item === null) continue;
    const instances = (item as { instances?: unknown }).instances;
    if (Array.isArray(instances)) {
      for (const inst of instances) {
        if (typeof inst === 'string' && inst.length > 4) result.push(inst.toLowerCase());
      }
    }
    const pat = (item as { pattern?: unknown }).pattern;
    if (typeof pat === 'string' && pat.length > 4) result.push(pat.toLowerCase());
  }
  return [...new Set(result)];
}

function parseMatomoYaml(text: string): string[] {
  const bots = new Set<string>();
  const metachar = /[\^$()\[\]*+?{}|]/g;
  for (const raw of text.split('\n')) {
    const s = raw.trim();
    if (!s.includes('regex:')) continue;
    let val = s.split('regex:').slice(1).join('regex:').trim();
    val = val.replace(/^['"]/, '').replace(/['"]$/, '');
    val = val.replace(metachar, '');
    val = val.replace(/\.\*/g, '').replace(/\(\?:/g, '').replace(/\(\?i\)/g, '').trim();
    if (val && val.length > 3) bots.add(val.toLowerCase());
  }
  return [...bots];
}

// ── Fetch ────────────────────────────────────────────────────────────────────

async function fetchFeed(urls: string[]): Promise<string | null> {
  for (const url of urls) {
    try {
      const resp = await fetch(url, {
        headers: { 'User-Agent': 'UAIntel-FeedRefresher/3.3 (+https://uaintel)' },
        cf: { cacheTtl: 0 },
      });
      if (resp.ok) {
        const text = await resp.text();
        if (text.length > 100) return text;
      }
    } catch {
      // try next url
    }
  }
  return null;
}

// ── Refresh (cron + manual trigger) ──────────────────────────────────────────

export async function refreshThreatFeeds(env: Env): Promise<FeedMeta> {
  const now = new Date().toISOString();
  const meta: FeedMeta = {
    last_update: now,
    sources: {},
    counts: { bad_bots: 0, malware: 0, crawlers: 0, matomo: 0 },
  };

  const badBots = new Set<string>();
  let malware: MalwareEntry[] = [];
  let crawlers: string[] = [];
  let matomo: string[] = [];

  for (const src of SOURCES) {
    const text = await fetchFeed(src.urls);
    let count = 0;
    const ok = text !== null;

    if (text) {
      try {
        switch (src.parse) {
          case 'plaintext': {
            const items = parsePlaintext(text);
            for (const i of items) if (i.trim()) badBots.add(i.toLowerCase());
            count = items.length;
            break;
          }
          case 'csv': {
            malware = parseMthchtCSV(text);
            count = malware.length;
            break;
          }
          case 'json_crawlers': {
            crawlers = parseCrawlersJson(text);
            count = crawlers.length;
            break;
          }
          case 'yaml': {
            matomo = parseMatomoYaml(text);
            count = matomo.length;
            break;
          }
        }
      } catch (e) {
        console.error(`parse error for ${src.key}:`, e);
      }
    }

    meta.sources[src.key] = { name: src.desc, ok, count, updated: ok ? now : 'failed' };
  }

  const badBotsArr = [...badBots];
  meta.counts = {
    bad_bots: badBotsArr.length,
    malware: malware.length,
    crawlers: crawlers.length,
    matomo: matomo.length,
  };

  // Only overwrite KV keys that actually parsed to data — never wipe good data
  // with an empty result from a transient upstream failure.
  const writes: Promise<unknown>[] = [];
  if (badBotsArr.length) writes.push(env.CACHE.put(KV_BAD_BOTS, JSON.stringify(badBotsArr)));
  if (malware.length) writes.push(env.CACHE.put(KV_MALWARE, JSON.stringify(malware)));
  if (crawlers.length) writes.push(env.CACHE.put(KV_CRAWLERS, JSON.stringify(crawlers)));
  if (matomo.length) writes.push(env.CACHE.put(KV_MATOMO, JSON.stringify(matomo)));
  writes.push(env.CACHE.put(KV_META, JSON.stringify(meta)));
  await Promise.all(writes);

  // Invalidate the in-isolate cache so the next read reflects the refresh.
  _cache = null;
  _cacheAt = 0;

  return meta;
}

// ── Load (analyze path) — per-isolate cache over KV, bundle fallback ─────────

let _cache: ThreatData | null = null;
let _cacheAt = 0;
const CACHE_TTL_MS = 5 * 60 * 1000;

export async function loadThreatData(env: Env): Promise<ThreatData | null> {
  const nowMs = Date.now();
  if (_cache && nowMs - _cacheAt < CACHE_TTL_MS) return _cache;

  try {
    const [bb, mw, cr, mt] = await Promise.all([
      env.CACHE.get(KV_BAD_BOTS),
      env.CACHE.get(KV_MALWARE),
      env.CACHE.get(KV_CRAWLERS),
      env.CACHE.get(KV_MATOMO),
    ]);
    if (!bb && !mw && !cr && !mt) return null; // nothing cached yet → caller uses bundle

    const data: ThreatData = {
      badBots: bb ? (JSON.parse(bb) as string[]) : [],
      malware: mw ? (JSON.parse(mw) as MalwareEntry[]) : [],
      crawlers: cr ? (JSON.parse(cr) as string[]) : [],
      matomo: mt ? (JSON.parse(mt) as string[]) : [],
    };
    _cache = data;
    _cacheAt = nowMs;
    return data;
  } catch (e) {
    console.error('loadThreatData error:', e);
    return null;
  }
}

export async function getFeedMeta(env: Env): Promise<FeedMeta | null> {
  try {
    const m = await env.CACHE.get(KV_META);
    return m ? (JSON.parse(m) as FeedMeta) : null;
  } catch {
    return null;
  }
}
