CREATE TABLE IF NOT EXISTS ua_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ua_hash TEXT UNIQUE NOT NULL,
  ua_string TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  total_lookups INTEGER DEFAULT 1,
  malicious_votes INTEGER DEFAULT 0,
  benign_votes INTEGER DEFAULT 0,
  bot_votes INTEGER DEFAULT 0,
  risk_score INTEGER DEFAULT 0,
  verdict TEXT DEFAULT 'Unknown',
  rule_flags TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS ua_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ua_hash TEXT NOT NULL,
  category TEXT NOT NULL,
  comment TEXT,
  reporter_ip TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ua_records_hash ON ua_records(ua_hash);
CREATE INDEX IF NOT EXISTS idx_ua_records_last_seen ON ua_records(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_ua_reports_hash ON ua_reports(ua_hash);
