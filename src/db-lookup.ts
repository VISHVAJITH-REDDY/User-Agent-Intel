/**
 * Layer 2 — Database Lookup Engine
 * Port of db_engine.py check logic using bundled data
 */

import { BAD_BOTS } from './data/bad-bots';
import { MALWARE_UAS } from './data/malware';
import { LEGITIMATE_CRAWLERS } from './data/crawlers';
import type { DBLookupResult, DBMatch } from './types';

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

export function lookupDatabases(ua: string): DBLookupResult {
  const uaLower = ua.toLowerCase();
  let scoreDelta = 0;
  const matches: DBMatch[] = [];
  const dbFlags: Array<{ type: string; label: string; severity: string }> = [];
  const sourcesHit: string[] = [];

  // --- Malware Intel check ---
  let malwareFound = false;

  // Exact match
  const malwareExact = MALWARE_UAS.find(m => {
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
    for (const m of MALWARE_UAS) {
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
    const badBotExact = BAD_BOTS.find(b => uaLower === b.toLowerCase());
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
      for (const bot of BAD_BOTS) {
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
  for (const c of LEGITIMATE_CRAWLERS) {
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

  return {
    score_delta: scoreDelta,
    matches,
    db_flags: dbFlags,
    db_score: scoreDelta,
    db_sources_hit: sourcesHit,
    db_counts: {
      bad_bots: BAD_BOTS.length,
      malware: MALWARE_UAS.length,
      crawlers: LEGITIMATE_CRAWLERS.length,
    },
  };
}
