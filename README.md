# Proxy Embed

A high-performance, dual-deployment reverse proxy system that routes and caches requests across multiple origin servers. Built with **Vercel Edge Functions** and **Cloudflare Workers** for maximum speed and reliability.

## Architecture Overview

```
Client ──► Vercel (proxy.js) ──► Cloudflare Worker (workers.js) ──► Origin Servers
```

The system consists of two components that work together:

| Component | Platform | File | Role |
|-----------|----------|------|------|
| **Edge Gateway** | Vercel Edge Functions | `proxy.js` | Lightweight front-door proxy — forwards requests to the worker |
| **Proxy Worker** | Cloudflare Workers | `workers.js` | Core proxy logic — load balancing, caching, security |

## Features

- **⚡ Intelligent Load Balancing** — Automatically routes requests to the fastest healthy origin server across multiple providers
- **📦 Smart Caching** — Different cache strategies per content type (video segments, images, manifests, etc.) with stale-while-revalidate support
- **🛡️ Built-in DDoS Protection** — Rate-limits aggressive IPs per path and redirects known bad actors
- **🔌 WebSocket Support** — Seamlessly proxies WebSocket connections through the load balancer
- **🌍 Full CORS Support** — Cross-Origin Resource Sharing enabled for all origins
- **⏱️ Configurable Timeouts** — 15-second upstream timeout with graceful 504/502 error responses
- **🔄 Origin Warmup** — Pre-warms serverless origin instances after a cache miss

## Quick Start

### Prerequisites

- Node.js 18+
- A Vercel account
- A Cloudflare account (for the Workers deployment)

### 1. Clone & Install

```bash
git clone <your-repo-url>
cd proxy-embed
npm install
```

### 2. Deploy the Cloudflare Worker

```bash
npx wrangler deploy
```

This deploys `workers.js` as your core proxy worker with load balancing and caching.

### 3. Deploy the Vercel Edge Function

Connect your repository to [Vercel](https://vercel.com) or use the Vercel CLI:

```bash
npx vercel deploy
```

The `vercel.json` configuration routes all traffic through `proxy.js`, which forwards requests to your Cloudflare Worker.

> **Note:** Update the `WORKER_URL` constant in `proxy.js` to point to your deployed Cloudflare Worker URL.

## Configuration

### Origins (`ORIGIN_URLS` in `workers.js`)

The worker tries the fastest origin among the configured list. Requests are retried against backup origins if the primary ones fail.

```js
const ORIGIN_URLS = [
  'https://primary-origin.example.com',
  'https://backup-origin.example.com',
];
```

### Cache TTLs (`CACHE_CONFIG` in `workers.js`)

| Content Type | Cache Duration | Example |
|--------------|----------------|---------|
| Video segments (.ts, .m4s) | 24 hours | HLS/DASH segments |
| Full media files | 7 days | .mp4, .mp3, images |
| Manifests (.m3u8, .mpd) | 12 hours | Playlist files |
| HTML/JS/CSS | 1 hour | Web pages & assets |
| API JSON | 0 (not cached) | Dynamic data |

### Security

- **Rate Limiting:** IPs exceeding 500 requests per path within 5 minutes are blocked for 5 minutes
- **Blocked IPs:** Hard-coded blocklist in `BLOCKED_IPS`
- **Internal Proxy Access:** Only trusted proxy IPs in `INTERNAL_PROXY_IPS` are allowed through

## Project Structure

```
├── proxy.js          # Vercel Edge Function — lightweight request forwarder
├── workers.js        # Cloudflare Worker — core proxy with all the logic
├── vercel.json       # Vercel deployment configuration
├── wrangler.toml     # Cloudflare Workers configuration
├── package.json
└── LICENSE
```

## API

The proxy works as a transparent HTTP/HTTPS proxy. Make requests to the deployed Vercel URL, and they will be forwarded through the system to the origin servers.

### Headers

| Header | Description |
|--------|-------------|
| `Access-Control-Allow-Origin: *` | CORS enabled for all origins |
| `X-Cache: HIT/MISS` | Whether the response came from cache |
| `Cache-Tag: path-<path>` | Cache tag for selective invalidation |

### Error Responses

| Status | Meaning |
|--------|---------|
| `502 Bad Gateway` | Could not reach any origin server |
| `504 Gateway Timeout` | Upstream server timed out (> 15s) |

## Development

```bash
# Run locally (if you have a local server)
npm start

# Deploy worker
npx wrangler deploy

# Deploy to Vercel
npx vercel deploy
```

## License

MIT — see [LICENSE](LICENSE) for details.

## Author

**Kenneth Panio**
