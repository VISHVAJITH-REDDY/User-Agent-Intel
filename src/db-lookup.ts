/**
 * Layer 2 — Database Lookup Engine
 * Port of db_engine.py check logic.
 *
 * Uses live threat data from KV when available (refreshed weekly by the cron in
 * feeds.ts); otherwise falls back to the bundled snapshot in src/data/*.
 */

import { BAD_BOTS } from './data/bad-bots';
import { MALWARE_UAS, type MalwareEntry } from './data/malware';
import { LEGITIMATE_CRAWLERS } from './data/crawlers';
import type { DBLookupResult, DBMatch, RuleFlag, ThreatData } from './types';

// Cap partial-match iteration to bound per-request cost (matches db_engine.py's [:5000]).
const MAX_PARTIAL_SCAN = 5000;

// Tokens that appear in virtually every real browser UA — skip partial matching on these
const BROWSER_NOISE_TOKENS = new Set([
  "mozilla", "mozilla/5.0", "mozilla/4.0",
  "applewebkit", "applewebkit/537.36", "webkit",
  "gecko", "like gecko", "khtml, like gecko",
  "chrome", "safari", "firefox", "opera", "msie", "trident",
  "windows", "windows nt", "win64", "win32", "x64", "x86_64",
  "macintosh", "mac os x", "linux", "android", "iphone", "ipad",
  "mobile", "desktop", "compatible",
  "intel mac os x", "cpu iphone os", "cpu os",
  "khtml",
]);

function isNoiseEntry(entry: string): boolean {
  const e = entry.trim().toLowerCase();
  if (BROWSER_NOISE_TOKENS.has(e)) return true;
  if (e.length < 8) return true;
  if (/^[\d./\s]+$/.test(e)) return true;
  const words = new Set(e.split(/[\s/;()]+/));
  const allNoise = [...words].every(w => !w || BROWSER_NOISE_TOKENS.has(w) || ['like', 'the', 'and', 'or'].includes(w));
  return allNoise;
}

// Strip glob wildcards for matching purposes
function stripGlobs(pattern: string): string {
  return pattern.replace(/\*/g, '').replace(/\?/g, '').trim();
}

export function lookupDatabases(ua: string, data?: ThreatData): DBLookupResult {
  // Live data from KV, or bundled fallback.
  const badBotList: string[] = data?.badBots ?? BAD_BOTS;
  const malwareList: MalwareEntry[] = data?.malware ?? MALWARE_UAS;
  const crawlerList: string[] = data?.crawlers ?? LEGITIMATE_CRAWLERS;
  const matomoList: string[] = data?.matomo ?? [];

  const uaLower = ua.toLowerCase();
  let scoreDelta = 0;
  const matches: DBMatch[] = [];
  const dbFlags: RuleFlag[] = [];
  const sourcesHit: string[] = [];

  // --- Malware Intel check ---
  let malwareFound = false;

  // Exact match
  const malwareExact = malwareList.find(m => {
    const mua = stripGlobs(m.ua).toLowerCase();
    return mua.length > 0 && uaLower === mua;
  });

  if (malwareExact) {
    malwareFound = true;
    scoreDelta += 75;
    matches.push({
      source: "mthcht Malware Intelligence",
      matched_pattern: malwareExact.ua,
      match_type: "exact",
      score_impact: 75,
    });
    dbFlags.push({
      type: "db_malware",
      label: `Malware UA: ${malwareExact.name} [${malwareExact.category}]`,
      severity: malwareExact.severity,
    });
    sourcesHit.push("mthcht Malware Intelligence");
  }

  // Partial match — require >= 12 chars, not noise
  if (!malwareFound) {
    let scanned = 0;
    for (const m of malwareList) {
      if (scanned++ >= MAX_PARTIAL_SCAN) break;
      const stripped = stripGlobs(m.ua).toLowerCase();
      if (stripped.length < 12) continue;
      if (isNoiseEntry(stripped)) continue;
      if (uaLower.includes(stripped)) {
        malwareFound = true;
        scoreDelta += 60;
        matches.push({
          source: "mthcht Malware Intelligence",
          matched_pattern: m.ua,
          match_type: "partial",
          score_impact: 60,
        });
        dbFlags.push({
          type: "db_malware",
          label: `Malware UA: ${m.name} [${m.category}]`,
          severity: m.severity,
        });
        sourcesHit.push("mthcht Malware Intelligence");
        break;
      }
    }
  }

  // --- Bad Bot check (only if no malware match) ---
  let badBotFound = false;
  if (!malwareFound) {
    // Exact match
    const badBotExact = badBotList.find(b => uaLower === b.toLowerCase());
    if (badBotExact) {
      badBotFound = true;
      scoreDelta += 60;
      matches.push({
        source: "Bad Bot Database",
        matched_pattern: badBotExact,
        match_type: "exact",
        score_impact: 60,
      });
      dbFlags.push({
        type: "db_bad_bot",
        label: "Listed in Bad Bot Database (exact match)",
        severity: "critical",
      });
      sourcesHit.push("Bad Bot Database");
    }

    // Partial match
    if (!badBotFound) {
      let scanned = 0;
      for (const bot of badBotList) {
        if (scanned++ >= MAX_PARTIAL_SCAN) break;
        const botLower = bot.toLowerCase();
        if (botLower.length < 8) continue;
        if (isNoiseEntry(botLower)) continue;
        if (uaLower.includes(botLower)) {
          badBotFound = true;
          scoreDelta += 45;
          matches.push({
            source: "Bad Bot Database",
            matched_pattern: bot,
            match_type: "partial",
            score_impact: 45,
          });
          dbFlags.push({
            type: "db_bad_bot",
            label: "Listed in Bad Bot Database (partial match)",
            severity: "high",
          });
          sourcesHit.push("Bad Bot Database");
          break;
        }
      }
    }
  }

  // --- Crawler check ---
  let crawlerFound = false;
  for (const c of crawlerList) {
    const cLower = c.toLowerCase();
    if (cLower.length < 8) continue;
    if (isNoiseEntry(cLower)) continue;
    if (uaLower.includes(cLower)) {
      crawlerFound = true;
      scoreDelta += -20;
      matches.push({
        source: "Crawler UA Database",
        matched_pattern: c,
        match_type: "partial",
        score_impact: -20,
      });
      dbFlags.push({
        type: "db_crawler",
        label: "Known Crawler — Crawler UA Database",
        severity: "info",
      });
      sourcesHit.push("Crawler UA Database");
      break;
    }
  }

  // --- Matomo bot check (only if not already flagged as a legit crawler) ---
  if (!crawlerFound) {
    let scanned = 0;
    for (const bot of matomoList) {
      if (scanned++ >= MAX_PARTIAL_SCAN) break;
      const botLower = bot.toLowerCase();
      if (botLower.length < 8) continue;
      if (isNoiseEntry(botLower)) continue;
      if (uaLower.includes(botLower)) {
        scoreDelta += 30;
        matches.push({
          source: "Matomo Device Detector",
          matched_pattern: bot,
          match_type: "partial",
          score_impact: 30,
        });
        dbFlags.push({
          type: "db_matomo",
          label: "Bot — Matomo Device Detector",
          severity: "medium",
        });
        sourcesHit.push("Matomo Device Detector");
        break;
      }
    }
  }

  return {
    score_delta: scoreDelta,
    matches,
    db_flags: dbFlags,
    db_score: scoreDelta,
    db_sources_hit: sourcesHit,
    db_counts: {
      bad_bots: badBotList.length,
      malware: malwareList.length,
      crawlers: crawlerList.length,
      matomo: matomoList.length,
    },
  };
}
