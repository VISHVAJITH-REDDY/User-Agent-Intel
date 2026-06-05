export interface AnalysisResult {
  ua_string: string;
  risk_score: number;
  verdict: string;
  verdict_color: string;
  rule_flags: string[];
  detection_sources: string[];
  db_matches: DBMatch[];
  community_stats: CommunityStats;
  analysis_time_ms: number;
}

export interface DBMatch {
  source: string;
  matched_pattern: string;
  match_type: string; // "exact" | "partial"
  score_impact: number;
}

export interface CommunityStats {
  total_votes: number;
  malicious_votes: number;
  benign_votes: number;
  bot_votes: number;
  community_boost: number;
}

export interface RuleEngineResult {
  score: number;
  flags: RuleFlag[];
}

export interface RuleFlag {
  type: string;
  label: string;
  severity: string;
}

export interface DBLookupResult {
  score_delta: number;
  matches: DBMatch[];
  db_flags: RuleFlag[];
  db_score: number;
  db_sources_hit: string[];
  db_counts: {
    bad_bots: number;
    malware: number;
    crawlers: number;
    matomo: number;
  };
}

/** Live threat data loaded from KV (refreshed weekly by the cron). */
export interface ThreatData {
  badBots: string[];
  malware: import('./data/malware').MalwareEntry[];
  crawlers: string[];
  matomo: string[];
}

export interface Env {
  DB: D1Database;
  CACHE: KVNamespace;
  RATE_LIMIT_ANALYZE: string;
  RATE_LIMIT_REPORT: string;
}
