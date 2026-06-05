# Deploying UAIntel to Cloudflare

## Prerequisites
- Cloudflare account (free tier works)
- Node.js 18+
- wrangler CLI: npm install -g wrangler

## Setup Steps

1. Login: wrangler login
2. Create D1 database: wrangler d1 create uaintel-community
   - Copy the database_id into wrangler.toml under [[d1_databases]]
3. Create KV namespace: wrangler kv:namespace create CACHE
   - Copy the id into wrangler.toml under [[kv_namespaces]]
4. Initialize DB schema: npm run db:init
5. Install deps: npm install
6. Deploy: npm run deploy

## Custom Domain
In Cloudflare dashboard → Workers → uaintel → Custom Domains
Add your domain, e.g.: ua.yourdomain.com

## Local Development
npm run dev

## Notes
- All detection databases are bundled at deploy time (no runtime downloads needed)
- D1 is used for community votes and recently-analyzed UA storage
- KV is used for rate limiting (per-IP per-minute counters)
- The weekly cron (wrangler.toml triggers.crons) is a placeholder hook for future DB refresh automation
