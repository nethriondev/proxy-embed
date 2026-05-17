# Proxy Embed

> A dual-deployment reverse proxy — runs as an **Express server** (Node.js / Vercel / Railway) or a **Cloudflare Worker** at the edge. Forwards HTTP/WebSocket requests to configurable backend URLs with rate limiting, IP filtering, proxy rotation/failover, smart caching, and media streaming support.

## Project Structure

```
index.js      — Process manager (spawns proxy.js with auto-restart)
proxy.js      — Express reverse proxy (Node.js / Vercel / Railway)
workers.js    — Cloudflare Workers edge deployment (standalone)
```

Two independent implementations (`proxy.js` and `workers.js`) that share the same core logic.

## How It Works

### 1. Process Manager (`index.js`)

Spawns `proxy.js` as a child process. If the `PID` environment variable is set to anything other than `"0"`, the process auto-restarts on crash — ideal for production deployments on Railway or similar platforms.

### 2. Express Proxy (`proxy.js`)

An Express server that acts as a middleman between clients and backend services:

- **Proxy targets** — Reads from `proxy-config.json`, `PROXY_URL`, or `PROXY_URLS` environment variable
- **Client IP detection** — Detects the real client IP via headers like `x-forwarded-for`, `cf-connecting-ip`, `x-real-ip`, `forwarded`, and Vercel-specific headers
- **Rate limiting** — Per-IP request tracking with configurable time window and max requests
- **IP blocking** — Static blocklist plus auto-ban after repeated violations
- **IP probing** — Probes banned/blocked IPs with HTTP requests (to detect when they come back online)
- **Proxy rotation** — Failover across multiple backend URLs on error (ECONNREFUSED, ETIMEDOUT, etc.)
- **Header forwarding** — Passes through `User-Agent`, `Accept`, `Authorization`, `Cookie`, `Referer`, `Origin`, and other headers
- **CORS** — Wildcard CORS headers on all responses
- **Streaming** — Optimized headers for SSE (`text/event-stream`) and streaming JSON
- **WebSocket** — Upgrade passthrough with rate limiting and IP filtering
- **Caching** — Smart `Cache-Control` headers based on content type

### 3. Cloudflare Worker (`workers.js`)

Same functionality deployed at the edge via Cloudflare Workers, plus:

- **Multi-origin failover** — Tries each origin URL in sequence, skipping 5xx errors
- **Smart caching** — Content-type-aware TTLs (HLS/DASH: 12h, images/video/audio: 12h, HTML: 1h, API/JSON/streams: no cache)
- **Range requests** — Partial content support for media streaming (`206 Partial Content`)
- **WebSocket pass-through** — Proxy WebSocket upgrade requests to origin servers
- **Cloudflare optimizations** — Polish (lossy image compression), Mirage (lazy loading), cache everything

## Quick Start

### Local Development

```bash
git clone <repo-url>
cd proxy-embed
npm install
npm start
```

The server starts on port `3000` by default.

### Deploy to Cloudflare Workers

```bash
npx wrangler deploy
```

## Configuration

### Method 1: Config File

Edit `proxy-config.json` in the project root:

```json
{
    "proxyUrls": ["https://your-backend.com"],
    "blockedIps": ["1.2.3.4"],
    "internalProxyIps": ["5.6.7.8"]
}
```

### Method 2: Environment Variables

```bash
# Single target
PROXY_URL=https://your-backend.com npm start

# Multiple targets (failover)
PROXY_URLS='["https://backup1.com","https://backup2.com"]' npm start
```

### Method 3: Cloudflare Workers

Edit the `ORIGIN_URLS` array at the top of `workers.js`:

```js
const ORIGIN_URLS = [
  'https://your-backend.com',
];
```

### Configuration Priority

`proxy-config.json` > `PROXY_URL` / `PROXY_URLS` env > default (`https://proxy-embed.nethriondev.workers.dev`)

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PROXY_URL` | Single backend target URL | — |
| `PROXY_URLS` | JSON array of backend URLs | — |
| `BLOCKED_IPS` | JSON array of IPs to block | `["72.60.237.246"]` |
| `INTERNAL_PROXY_IPS` | JSON array of trusted proxy IPs (bypass rate limits) | `["162.220.234.134"]` |
| `PORT` | Server port | `3000` |
| `RATE_LIMIT_WINDOW_MS` | Rate limit time window (ms) | `60000` (1 min) |
| `MAX_REQUESTS_PER_WINDOW` | Max requests per window per IP | `200` |
| `BAN_THRESHOLD` | Violations before auto-ban | `3` |
| `BAN_DURATION_MS` | Auto-ban duration (ms) | `900000` (15 min) |
| `MAX_TRACKED_IPS` | Max tracked IPs in memory | `100000` |
| `PID` | Set to `"0"` to disable auto-restart | — |

## Rate Limiting & IP Blocking

- Each IP is tracked by request **frequency** (requests per time window)
- After `BAN_THRESHOLD` violations, the IP is **auto-banned** for `BAN_DURATION_MS`
- Expired bans and stale tracking data are cleaned up every 15 seconds
- Trusted/internal proxy IPs bypass all rate limiting and blocking

### Behavior by Platform

| Action | Express (proxy.js) | Workers (workers.js) |
|--------|-------------------|---------------------|
| Rate limited | Socket destroyed | `429 Too Many Requests` |
| Banned | HTTP redirect to `http://{ip}` | `429 Too Many Requests` |
| Blocklisted | HTTP redirect to `http://{ip}` | `403 Forbidden` |

> **Note:** The Express version redirects banned IPs to their own IP address as a probing mechanism (to detect when the IP comes back online). The Worker version returns proper HTTP status codes.

## Proxy Rotation & Failover

When a proxy URL encounters an error (`ECONNREFUSED`, `ETIMEDOUT`, etc.):

- **Multiple URLs configured** — Rotates to the next URL in the list and returns a `502`/`504` with info about the next proxy
- **Single URL configured** — Returns the error directly with a note that rotation is disabled

## Streaming & Media Support

- **SSE / Streaming JSON** — `text/event-stream` and `application/stream+json` responses get `no-cache`, `no-transform`, and `no content-length` headers for proper streaming
- **Range requests** — `206 Partial Content` responses preserve `Content-Range` and set `Accept-Ranges: bytes` for video/audio seeking
- **HLS / DASH** — `.m3u8`, `.mpd`, `.ts`, `.m4s` segments are cached aggressively (12h TTL)

## CORS

All endpoints include:

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization, Accept, X-Stream, Range
Access-Control-Expose-Headers: *
```

## Caching Strategy

Both deployments apply content-type-aware `Cache-Control` headers:

| Content Type | Cache TTL | Example |
|-------------|-----------|---------|
| HLS/DASH playlists & segments | 12 hours | `.m3u8`, `.mpd`, `.ts`, `.m4s` |
| Images | 12 hours | `.jpg`, `.png`, `.gif`, `.webp`, `.svg` |
| Video | 12 hours | `.mp4`, `.webm`, `.avi`, `.mov` |
| Audio | 12 hours | `.mp3`, `.wav`, `.ogg`, `.m4a` |
| HTML | 1 hour | — |
| API / JSON / SSE | No cache | `/api/*` paths, `.json` |
| Error responses (non-200/206) | No cache | — |
| Range requests | 1 hour | — |

## Deployments

| Platform | Entry Point | Config Source |
|----------|-------------|---------------|
| Node.js / Railway | `index.js` | `proxy-config.json` or env vars |
| Vercel | `proxy.js` (serverless) | `vercel.json` + env vars |
| Cloudflare Workers | `workers.js` | `wrangler.toml` / edit `ORIGIN_URLS` |

## WebSocket Support

WebSocket upgrades (`Upgrade: websocket`) are supported in both deployments:

- **Express** — Full WebSocket proxy with rate limiting and IP filtering. Connects to the configured proxy URLs using `wss://` protocol
- **Workers** — WebSocket requests are forwarded directly to origin servers with failover

## License

MIT © Kenneth Panio
