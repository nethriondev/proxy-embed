# Proxy Embed

A reverse proxy with automatic failover support for multiple backend URLs.

## Benefits

### Security
- **Hides your real backend** - Attackers cannot directly target your origin server
- **Reduces attack surface** - Only the proxy is exposed, not your infrastructure
- **Easy to rotate** - Change proxy URLs instantly without touching your backend
- **Leverages platform security** - Cloudflare Workers and Vercel include built-in DDoS protection

### Reliability
- **Auto failover** - If primary proxy dies, automatically switches to backups without downtime
- **Preserves client IP** - Forwards original IP addresses to your backend
- **Streaming support** - Handles live streams and event-source responses

### Compatibility
- **CORS ready** - Works out of the box with any frontend
- **Deploy anywhere** - Works on Vercel, Railway, or any Node.js host

## Setup Options

Choose one of three ways to configure your proxy URLs:

### Option 1: JSON File (proxy-config.json)
```json
{
    "proxyUrls": [
        "https://proxy1.workers.dev",
        "https://proxy2.workers.dev",
        "https://proxy3.workers.dev"
    ]
}
```

Option 2: Environment Variable

```bash
PROXY_URLS='["https://proxy1.workers.dev","https://proxy2.workers.dev","https://proxy3.workers.dev"]'
```

Priority: JSON file → Environment variable → Default

## Screenshots
Before:
![Before](https://raw.githubusercontent.com/nethriondev/proxy-embed/main/screenshots/before.jpg)
After:
![After](https://raw.githubusercontent.com/nethriondev/proxy-embed/main/screenshots/after.jpg)

## Quick Start

1. Install dependencies:
   ```bash
   npm install
   ```
2. Create proxy-config.json or set PROXY_URLS environment variable
3. Run:
   ```bash
   npm start
   ```

## Deploy to Vercel

Set environment variable PROXY_URLS in Vercel dashboard:

```
PROXY_URLS='["https://proxy1.workers.dev","https://proxy2.workers.dev"]'
```

### How Failover Works

When a request fails, the proxy immediately switches to the next URL in your list. No counting, no waiting, no downtime.