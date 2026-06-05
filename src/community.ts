/**
 * Layer 3 — Community Database (D1)
 * Port of community_db.py using Cloudflare D1 and Web Crypto API
 */

import type { Env, CommunityStats } from './types';

// SHA-256 using Web Crypto API (available in Cloudflare Workers)
export async function hashUA(ua: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(ua.trim());
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex.slice(0, 16);
}

export async function storeAnalysisResult(
  env: Env,
  ua: string,
  uaHash: string,
  score: number,
  verdict: string,
  flags: string[]
): Promise<void> {
  const now = new Date().toISOString();
  const flagsJson = JSON.stringify(flags);

  try {
    // Check if record exists
    const existing = await env.DB
      .prepare("SELECT id FROM ua_records WHERE ua_hash = ?")
      .bind(uaHash)
      .first<{ id: number }>();

    if (existing) {
      await env.DB
        .prepare(`UPDATE ua_records
          SET last_seen = ?, total_lookups = total_lookups + 1,
              risk_score = ?, verdict = ?, rule_flags = ?
          WHERE ua_hash = ?`)
        .bind(now, score, verdict, flagsJson, uaHash)
        .run();
    } else {
      await env.DB
        .prepare(`INSERT INTO ua_records
          (ua_hash, ua_string, first_seen, last_seen, total_lookups, risk_score, verdict, rule_flags)
          VALUES (?, ?, ?, ?, 1, ?, ?, ?)`)
        .bind(uaHash, ua, now, now, score, verdict, flagsJson)
        .run();
    }
  } catch (e) {
    console.error("storeAnalysisResult error:", e);
  }
}

export async function getCommunityStats(env: Env, uaHash: string): Promise<CommunityStats & {
  found: boolean;
  total_lookups?: number;
  first_seen?: string;
  last_seen?: string;
  confidence_malicious?: number;
  comments?: Array<{ category: string; comment: string; created_at: string }>;
}> {
  try {
    const row = await env.DB
      .prepare("SELECT * FROM ua_records WHERE ua_hash = ?")
      .bind(uaHash)
      .first<{
        total_lookups: number;
        first_seen: string;
        last_seen: string;
        malicious_votes: number;
        benign_votes: number;
        bot_votes: number;
      }>();

    if (!row) {
      return {
        found: false,
        total_votes: 0,
        malicious_votes: 0,
        benign_votes: 0,
        bot_votes: 0,
        community_boost: 0,
        comments: [],
      };
    }

    const mv = row.malicious_votes || 0;
    const bv = row.benign_votes || 0;
    const botv = row.bot_votes || 0;
    const totalVotes = mv + bv + botv;
    const confidenceMalicious = totalVotes > 0 ? Math.round((mv / totalVotes) * 100) : 0;
    const communityBoost = confidenceMalicious > 70 ? Math.min(15, Math.floor(confidenceMalicious / 7)) : 0;

    const commentsResult = await env.DB
      .prepare(`SELECT category, comment, created_at FROM ua_reports
        WHERE ua_hash = ? ORDER BY created_at DESC LIMIT 10`)
      .bind(uaHash)
      .all<{ category: string; comment: string; created_at: string }>();

    const comments = (commentsResult.results || [])
      .filter(r => r.comment)
      .map(r => ({
        category: r.category,
        comment: r.comment,
        created_at: (r.created_at || "").slice(0, 16).replace("T", " "),
      }));

    return {
      found: true,
      total_lookups: row.total_lookups || 1,
      first_seen: (row.first_seen || "").slice(0, 10),
      last_seen: (row.last_seen || "").slice(0, 10),
      total_votes: totalVotes,
      malicious_votes: mv,
      benign_votes: bv,
      bot_votes: botv,
      community_boost: communityBoost,
      confidence_malicious: confidenceMalicious,
      comments,
    };
  } catch (e) {
    console.error("getCommunityStats error:", e);
    return {
      found: false,
      total_votes: 0,
      malicious_votes: 0,
      benign_votes: 0,
      bot_votes: 0,
      community_boost: 0,
      comments: [],
    };
  }
}

export async function submitReport(
  env: Env,
  uaHash: string,
  category: string,
  comment: string,
  reporterIp: string
): Promise<void> {
  const now = new Date().toISOString();

  try {
    const colMap: Record<string, string> = {
      malicious: "malicious_votes",
      benign: "benign_votes",
      bot: "bot_votes",
    };
    const col = colMap[category];

    if (col) {
      await env.DB
        .prepare(`UPDATE ua_records SET ${col} = ${col} + 1 WHERE ua_hash = ?`)
        .bind(uaHash)
        .run();
    }

    if (comment.trim()) {
      await env.DB
        .prepare(`INSERT INTO ua_reports (ua_hash, category, comment, reporter_ip, created_at)
          VALUES (?, ?, ?, ?, ?)`)
        .bind(uaHash, category, comment.trim(), reporterIp, now)
        .run();
    }
  } catch (e) {
    console.error("submitReport error:", e);
  }
}

export async function getRecentlyReported(env: Env, limit = 15): Promise<Array<{
  ua_string: string;
  verdict: string;
  risk_score: number;
  last_seen: string;
  malicious_votes: number;
  total_lookups: number;
}>> {
  try {
    const result = await env.DB
      .prepare(`SELECT ua_string, verdict, risk_score, last_seen,
        malicious_votes, total_lookups FROM ua_records
        WHERE malicious_votes > 0 OR risk_score > 30
        ORDER BY last_seen DESC LIMIT ?`)
      .bind(limit)
      .all<{
        ua_string: string;
        verdict: string;
        risk_score: number;
        last_seen: string;
        malicious_votes: number;
        total_lookups: number;
      }>();

    return result.results || [];
  } catch (e) {
    console.error("getRecentlyReported error:", e);
    return [];
  }
}

export async function getStatsSummary(env: Env): Promise<{
  total_uas: number;
  malicious_uas: number;
  total_reports: number;
}> {
  try {
    const total = await env.DB
      .prepare("SELECT COUNT(*) as cnt FROM ua_records")
      .first<{ cnt: number }>();
    const malicious = await env.DB
      .prepare("SELECT COUNT(*) as cnt FROM ua_records WHERE verdict IN ('Malicious', 'Likely Malicious')")
      .first<{ cnt: number }>();
    const reports = await env.DB
      .prepare("SELECT COUNT(*) as cnt FROM ua_reports")
      .first<{ cnt: number }>();

    return {
      total_uas: total?.cnt || 0,
      malicious_uas: malicious?.cnt || 0,
      total_reports: reports?.cnt || 0,
    };
  } catch (e) {
    console.error("getStatsSummary error:", e);
    return { total_uas: 0, malicious_uas: 0, total_reports: 0 };
  }
}
