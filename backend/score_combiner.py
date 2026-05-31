"""Score Combiner — merges all 3 layers into final verdict."""


def combine_scores(rule_result: dict, db_result: dict, community: dict) -> dict:
    base = rule_result["risk_score"]

    # DB delta
    db_delta = db_result.get("db_score", 0)
    base = max(0, min(100, base + db_delta))

    # Community boost
    community_boost = 0
    if community.get("found") and community.get("confidence_malicious", 0) > 70:
        community_boost = min(15, community["confidence_malicious"] // 7)
        base = min(100, base + community_boost)

    # Verdict
    if base <= 20:   verdict, color = "Legitimate",       "green"
    elif base <= 50: verdict, color = "Suspicious",       "yellow"
    elif base <= 75: verdict, color = "Likely Malicious", "orange"
    else:            verdict, color = "Malicious",        "red"

    all_flags = rule_result.get("flags", []) + db_result.get("db_flags", [])

    sources = []
    if rule_result.get("flags"):
        sources.append("Rule Engine")
    sources.extend(db_result.get("db_sources_hit", []))
    if community.get("found") and community.get("total_votes", 0) > 0:
        sources.append(f"Community ({community['total_votes']} votes)")

    return {
        "risk_score":      base,
        "verdict":         verdict,
        "verdict_color":   color,
        "flags":           all_flags,
        "flag_count":      len(all_flags),
        "detection_sources": sources,
        "score_breakdown": {
            "rule_engine":      rule_result["risk_score"],
            "db_delta":         db_delta,
            "community_boost":  community_boost,
            "final":            base,
        },
        "db_loaded": db_result.get("db_loaded", False),
        "db_counts": db_result.get("db_counts", {}),
    }
