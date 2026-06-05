/**
 * UAIntel v3.3 — Cloudflare Workers (Hono)
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import type { Env } from './types';
import { analyzeRuleEngine } from './analyzer';
import { lookupDatabases } from './db-lookup';
import {
  hashUA,
  storeAnalysisResult,
  getCommunityStats,
  submitReport,
  getRecentlyReported,
  getStatsSummary,
} from './community';
import { combineScores } from './scorer';
import { loadThreatData, refreshThreatFeeds, getFeedMeta } from './feeds';
import { BAD_BOTS } from './data/bad-bots';
import { MALWARE_UAS } from './data/malware';
import { LEGITIMATE_CRAWLERS } from './data/crawlers';

const app = new Hono<{ Bindings: Env }>();

app.use('*', cors());

// ── Rate Limiting via KV ──────────────────────────────────────────────────────
async function checkRateLimit(env: Env, ip: string, endpoint: string, limit: number): Promise<boolean> {
  const key = `rl:${ip}:${endpoint}:${Math.floor(Date.now() / 60000)}`;
  try {
    const current = await env.CACHE.get(key);
    const count = current ? parseInt(current) : 0;
    if (count >= limit) return true; // rate limited
    await env.CACHE.put(key, String(count + 1), { expirationTtl: 120 });
    return false;
  } catch {
    // If KV is unavailable, allow the request
    return false;
  }
}

function getClientIp(request: Request): string {
  const xff = request.headers.get('cf-connecting-ip') ||
    request.headers.get('x-forwarded-for') ||
    request.headers.get('x-real-ip');
  if (xff) return xff.split(',')[0].trim();
  return 'unknown';
}

// ── POST /analyze ─────────────────────────────────────────────────────────────
app.post('/analyze', async (c) => {
  const ip = getClientIp(c.req.raw);
  const rateLimit = parseInt(c.env.RATE_LIMIT_ANALYZE || '30');

  if (await checkRateLimit(c.env, ip, 'analyze', rateLimit)) {
    return c.json({ error: `Rate limit exceeded. Max ${rateLimit} requests/minute.` }, 429);
  }

  let body: { user_agent?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }

  const ua = (body.user_agent || '').trim();
  if (!ua) {
    return c.json({ error: 'User-Agent string cannot be empty' }, 400);
  }
  if (ua.length > 2000) {
    return c.json({ error: 'User-Agent string too long (max 2000 chars)' }, 400);
  }

  const t0 = Date.now();

  // Layer 1: Rule Engine
  const ruleResult = analyzeRuleEngine(ua);

  // Layer 2: DB Lookup — prefer live KV data (weekly cron), fall back to bundle
  const liveData = await loadThreatData(c.env);
  const dbResult = lookupDatabases(ua, liveData ?? undefined);

  // Layer 3: Community Stats
  const uaHashStr = await hashUA(ua);
  const communityStats = await getCommunityStats(c.env, uaHashStr);

  // Combine Scores
  const combined = combineScores({
    ruleScore: ruleResult.score,
    ruleFlags: ruleResult.flags,
    dbDelta: dbResult.db_score,
    dbFlags: dbResult.db_flags,
    dbSourcesHit: dbResult.db_sources_hit,
    communityStats,
  });

  // Persist to D1 (background - don't await)
  c.executionCtx.waitUntil(
    storeAnalysisResult(
      c.env,
      ua,
      uaHashStr,
      combined.finalScore,
      combined.verdict,
      combined.allFlags.map(f => f.label)
    )
  );

  return c.json({
    parsed: ruleResult.parsed,
    flags: combined.allFlags,
    flag_count: combined.allFlags.length,
    risk_score: combined.finalScore,
    verdict: combined.verdict,
    verdict_color: combined.verdictColor,
    detection_sources: combined.detectionSources,
    score_breakdown: combined.scoreBreakdown,
    db_loaded: true,
    db_counts: dbResult.db_counts,
    community: communityStats,
    crawler: ruleResult.crawler,
    analysis_time_ms: Date.now() - t0,
  });
});

// ── POST /report ──────────────────────────────────────────────────────────────
app.post('/report', async (c) => {
  const ip = getClientIp(c.req.raw);
  const rateLimit = parseInt(c.env.RATE_LIMIT_REPORT || '10');

  if (await checkRateLimit(c.env, ip, 'report', rateLimit)) {
    return c.json({ error: 'Rate limit exceeded.' }, 429);
  }

  let body: { user_agent?: string; category?: string; comment?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }

  const ua = (body.user_agent || '').trim();
  const category = (body.category || '').trim();
  const comment = (body.comment || '').trim();

  if (!ua) return c.json({ error: 'user_agent is required' }, 400);
  if (!['malicious', 'benign', 'bot'].includes(category)) {
    return c.json({ error: 'category must be: malicious, benign, or bot' }, 400);
  }

  const uaHashStr = await hashUA(ua);
  await submitReport(c.env, uaHashStr, category, comment, ip);

  return c.json({ success: true, message: 'Report submitted — thank you!' });
});

// ── GET /recent ───────────────────────────────────────────────────────────────
app.get('/recent', async (c) => {
  const results = await getRecentlyReported(c.env, 15);
  return c.json(results);
});

// ── GET /stats ────────────────────────────────────────────────────────────────
app.get('/stats', async (c) => {
  const stats = await getStatsSummary(c.env);
  return c.json(stats);
});

// ── GET /db-status ────────────────────────────────────────────────────────────
app.get('/db-status', async (c) => {
  const communityStats = await getStatsSummary(c.env);
  const meta = await getFeedMeta(c.env);
  const live = await loadThreatData(c.env);
  const isLive = live !== null;

  // Live counts from KV when present, otherwise bundled snapshot sizes.
  const badBotsCount = live?.badBots.length ?? BAD_BOTS.length;
  const malwareCount = live?.malware.length ?? MALWARE_UAS.length;
  const crawlersCount = live?.crawlers.length ?? LEGITIMATE_CRAWLERS.length;
  const matomoCount = live?.matomo.length ?? 0;

  const src = (key: string, fallbackName: string, count: number) => {
    const m = meta?.sources?.[key];
    return {
      name: m?.name ?? fallbackName,
      loaded: m ? m.ok : true,
      last_updated: m?.updated ?? 'Bundled at build time',
      entry_count: m?.count ?? count,
    };
  };

  return c.json({
    nginx_bots: src('nginx_bots', 'Nginx Bad Bot Blocker', Math.floor(BAD_BOTS.length * 0.4)),
    apache_bots: src('apache_bots', 'Apache Bad Bot Blocker', Math.floor(BAD_BOTS.length * 0.4)),
    seclists_ua: src('seclists_ua', 'SecLists UA Database', Math.floor(BAD_BOTS.length * 0.2)),
    mthcht_malware: src('mthcht_malware', 'mthcht Malware Intel', malwareCount),
    crawlers: src('crawlers', 'Crawler UA Database', crawlersCount),
    matomo_bots: src('matomo_bots', 'Matomo Device Detector', matomoCount),
    db_loaded: true,
    source: isLive ? 'live (KV, weekly cron)' : 'bundled snapshot',
    last_auto_update: meta?.last_update ?? 'Bundled at build time',
    next_update: 'Weekly (Sunday 00:00 UTC) or POST /db-update',
    in_memory: {
      bad_bots_combined: badBotsCount,
      malware_intel: malwareCount,
      crawlers: crawlersCount,
      matomo_bots: matomoCount,
      total: badBotsCount + malwareCount + crawlersCount + matomoCount,
    },
    community_db: communityStats,
  });
});

// ── POST /db-update ───────────────────────────────────────────────────────────
// Manually trigger a threat-feed refresh. Runs in the background; returns at once.
app.post('/db-update', async (c) => {
  c.executionCtx.waitUntil(
    refreshThreatFeeds(c.env)
      .then((m) => console.log('Manual DB refresh complete:', JSON.stringify(m.counts)))
      .catch((e) => console.error('Manual DB refresh failed:', e))
  );
  return c.json({ success: true, message: 'Threat-feed refresh triggered in the background.' });
});

// ── GET /health ───────────────────────────────────────────────────────────────
app.get('/health', (c) => {
  return c.json({ status: 'ok', service: 'UAIntel', version: '3.3.0' });
});

// ── GET / ─────────────────────────────────────────────────────────────────────
// Workers Assets ([assets] in wrangler.toml) serves /public/index.html at "/"
// automatically and only invokes this Worker for non-asset paths. This route is
// a harmless fallback in case the asset isn't matched.
app.get('/', (c) => {
  return c.redirect('/index.html');
});

// ── Exports ───────────────────────────────────────────────────────────────────
export default {
  fetch: app.fetch,
  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    // Weekly cron: re-fetch the six upstream threat feeds and cache them in KV.
    console.log('UAIntel weekly cron triggered — refreshing threat feeds...');
    ctx.waitUntil(
      refreshThreatFeeds(env)
        .then((m) => console.log('Cron DB refresh complete:', JSON.stringify(m.counts)))
        .catch((e) => console.error('Cron DB refresh failed:', e))
    );
  },
};
