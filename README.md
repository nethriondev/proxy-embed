# Proxy Embed

A dual-deployment reverse proxy — runs as an **Express server** (Node.js/Vercel) or a **Cloudflare Worker**. Forwards HTTP requests to a configurable backend URL with rate limiting, IP filtering, proxy rotation/failover, and intelligent caching (Workers).

## Architecture

```
index.js  (process manager - spawns proxy.js with auto-restart)
  └── proxy.js  (Express reverse proxy - runs on Node.js/Vercel)

workers.js  (Cloudflare Workers - edge-deployed standalone)
```

Both `proxy.js` and `workers.js` implement the same core logic independently.

## How It Works

1. **index.js** spawns `proxy.js` as a child process. If the `PID` env var is set to anything other than `"0"`, it auto-restarts the process on crash.
2. **proxy.js** runs an Express server that:
   - Reads proxy targets from `proxy-config.json`, `PROXY_URL`, or `PROXY_URLS` env
   - Detects client IP via `x-forwarded-for`, `cf-connecting-ip`, `x-real-ip`, and other headers
   - Enforces per-IP rate limiting (configurable window & max requests)
   - Limits concurrent connections per IP
   - Blocks specific IPs (static blocklist) and auto-bans IPs after repeated violations
   - Rotates through proxy URLs on error (failover)
   - Forwards original client IP to backend via headers
   - Sets CORS headers on all responses
3. **workers.js** does the same at the edge with Cloudflare Workers, plus:
   - Multi-origin failover (tries each origin URL in sequence)
   - Intelligent caching: different TTLs per content type (HLS/DASH segments: 12h, images/video/audio: 12h, HTML: 1h, API/JSON/streams: no cache)
   - Range request support for media streaming
   - WebSocket pass-through

## Setup

### Node.js / Vercel

```bash
npm install
npm start
```

Set proxy targets via `proxy-config.json`:
```json
{
    "proxyUrls": ["https://your-backend.com"],
    "blockedIps": ["1.2.3.4"],
    "internalProxyIps": ["5.6.7.8"]
}
```

Or via environment variables:
```bash
PROXY_URL=https://your-backend.com npm start
PROXY_URLS='["https://backup1.com","https://backup2.com"]' npm start
```

### Cloudflare Workers

Deploy `workers.js` via `wrangler`:
```bash
npx wrangler deploy
```

Edit `ORIGIN_URLS` array in `workers.js` to set backend targets.

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PROXY_URL` | Single proxy target URL | — |
| `PROXY_URLS` | JSON array of proxy target URLs | — |
| `BLOCKED_IPS` | JSON array of IPs to block | `["72.60.237.246"]` |
| `INTERNAL_PROXY_IPS` | JSON array of trusted proxy IPs (bypass rate limits) | `["162.220.234.134"]` |
| `PORT` | Server port | `3000` |
| `RATE_LIMIT_WINDOW_MS` | Rate limit time window | `10000` (10s) |
| `MAX_REQUESTS_PER_WINDOW` | Max requests per window per IP | `500` |
| `MAX_CONCURRENT_PER_IP` | Max concurrent connections per IP | `100` |
| `BAN_THRESHOLD` | Violations before auto-ban | `3` |
| `BAN_DURATION_MS` | Auto-ban duration | `300000` (5min) |
| `MAX_TRACKED_IPS` | Max tracked IPs in memory | `10000` |
| `PID` | Set to `"0"` to disable auto-restart | — |

### Priority

`proxy-config.json` > `PROXY_URL`/`PROXY_URLS` env > default (`https://proxy-embed.nethriondev.workers.dev`)

## Rate Limiting & IP Blocking

- Each IP is tracked for request frequency and concurrent connections
- Violations accumulate; after `BAN_THRESHOLD` violations, the IP is auto-banned for `BAN_DURATION_MS`
- Expired bans and stale tracking data are cleaned every 15 seconds
- Trusted/internal proxy IPs bypass all rate limiting and blocking

## Streaming & CORS

- All responses get `access-control-allow-origin: *`
- Streaming responses (`text/event-stream`, `application/stream+json`, or `x-stream: true` header) get optimized headers (`no-cache`, `no-transform`, no `content-length`)
- CORS preflight (`OPTIONS`) is handled with wildcard allow

## Proxy Rotation & Failover

When a proxy URL errors (ECONNREFUSED, ETIMEDOUT, etc.), the server rotates to the next URL in the list. With only one URL configured, rotation is disabled and the error is returned directly.

## Deployments

| Platform | Entry | Config |
|----------|-------|--------|
| Node.js / Railway | `index.js` | `proxy-config.json` or env vars |
| Vercel | `index.js` (serverless) | `vercel.json` |
| Cloudflare Workers | `workers.js` | `wrangler.toml` / edit `ORIGIN_URLS` |
