/**
 * Score Combiner — merges rule engine + DB + community into final verdict
 * Port of score_combiner.py
 */

import type { CommunityStats } from './types';

interface CombineScoresInput {
  ruleScore: number;
  ruleFlags: Array<{ type: string; label: string; severity: string }>;
  dbDelta: number;
  dbFlags: Array<{ type: string; label: string; severity: string }>;
  dbSourcesHit: string[];
  communityStats: CommunityStats & {
    found?: boolean;
    total_votes?: number;
    confidence_malicious?: number;
    community_boost?: number;
  };
}

interface CombineScoresResult {
  finalScore: number;
  verdict: string;
  verdictColor: string;
  allFlags: Array<{ type: string; label: string; severity: string }>;
  detectionSources: string[];
  scoreBreakdown: {
    rule_engine: number;
    db_delta: number;
    community_boost: number;
    final: number;
  };
}

export function combineScores(input: CombineScoresInput): CombineScoresResult {
  let base = input.ruleScore;

  // Apply DB delta
  const dbDelta = input.dbDelta;
  base = Math.max(0, Math.min(100, base + dbDelta));

  // Community boost
  let communityBoost = 0;
  const comm = input.communityStats;
  if (comm.found && (comm.confidence_malicious ?? 0) > 70) {
    communityBoost = Math.min(15, Math.floor((comm.confidence_malicious ?? 0) / 7));
    base = Math.min(100, base + communityBoost);
  }

  // Verdict
  let verdict: string;
  let verdictColor: string;
  if (base <= 20) { verdict = "Legitimate"; verdictColor = "green"; }
  else if (base <= 50) { verdict = "Suspicious"; verdictColor = "yellow"; }
  else if (base <= 75) { verdict = "Likely Malicious"; verdictColor = "orange"; }
  else { verdict = "Malicious"; verdictColor = "red"; }

  const allFlags = [...input.ruleFlags, ...input.dbFlags];

  const detectionSources: string[] = [];
  if (input.ruleFlags.length > 0) detectionSources.push("Rule Engine");
  detectionSources.push(...input.dbSourcesHit);
  const totalVotes = comm.total_votes ?? 0;
  if (comm.found && totalVotes > 0) {
    detectionSources.push(`Community (${totalVotes} votes)`);
  }

  return {
    finalScore: base,
    verdict,
    verdictColor,
    allFlags,
    detectionSources,
    scoreBreakdown: {
      rule_engine: input.ruleScore,
      db_delta: dbDelta,
      community_boost: communityBoost,
      final: base,
    },
  };
}
