# Proxy Embed

A reverse proxy with advanced load balancing, automatic failover, and health monitoring for multiple backend URLs.

## Benefits

### Security
- **Hides your real backend** - Attackers cannot directly target your origin server
- **Reduces attack surface** - Only the proxy is exposed, not your infrastructure
- **Easy to rotate** - Change proxy URLs instantly without touching your backend
- **Leverages platform security** - Cloudflare Workers and Vercel include built-in DDoS protection

### Reliability
- **Auto failover** - If primary proxy dies, automatically switches to backups without downtime
- **Active health checks** - Monitors server health and marks unhealthy servers automatically
- **Auto retry** - Automatically retries failed requests on the next available server
- **Server recovery** - Automatically brings servers back online when they recover
- **Preserves client IP** - Forwards original IP addresses to your backend
- **Streaming support** - Handles live streams and event-source responses with optimized headers

### Performance
- **7 load balancing algorithms** - Choose the best strategy for your workload
- **Weighted routing** - Distribute traffic based on server capacity
- **Response time tracking** - Route to fastest responding servers
- **Connection tracking** - Balances active connections across servers

### Compatibility
- **CORS ready** - Works out of the box with any frontend
- **Deploy anywhere** - Works on Vercel, Railway, or any Node.js host
- **Multi-platform IP detection** - Supports Cloudflare, Vercel, and standard proxies

## Setup Options

### Configuration Files

Create `proxy-config.json` for static proxy URL configuration:
```json
{
    "proxyUrls": [
        "https://proxy1.workers.dev",
        "https://proxy2.workers.dev",
        "https://proxy3.workers.dev"
    ]
}
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PROXY_URL` | Single proxy URL | - |
| `PROXY_URLS` | JSON array of proxy URLs | - |
| `PROXY_WEIGHTS` | Comma-separated url:weight pairs | - |
| `LB_ALGORITHM` | Load balancing algorithm | `round-robin` |
| `HEALTH_CHECK_INTERVAL` | Health check interval (ms) | `30000` |
| `HEALTH_CHECK_TIMEOUT` | Health check timeout (ms) | `5000` |
| `FAILURE_THRESHOLD` | Failures before marking unhealthy | `3` |

### Load Balancing Algorithms

Choose the best algorithm for your use case:

| Algorithm | Description |
|-----------|-------------|
| `round-robin` | Cycles through servers sequentially (default) |
| `least-connections` | Routes to server with fewest active connections |
| `weighted-round-robin` | Distributes based on server weights |
| `weighted-least-connections` | Balances connections relative to weight |
| `ip-hash` | Consistent routing by client IP |
| `least-response-time` | Routes to fastest responding server |
| `random` | Random server selection |

Example weighted configuration:
```bash
PROXY_URLS='["https://proxy1.workers.dev","https://proxy2.workers.dev"]'
PROXY_WEIGHTS="https://proxy1.workers.dev:3,https://proxy2.workers.dev:1"
```

Priority: JSON file → Environment variable → Default

## Screenshots
### Before:
![Before](https://raw.githubusercontent.com/nethriondev/proxy-embed/main/screenshots/before.jpg)

### After:
![After](https://raw.githubusercontent.com/nethriondev/proxy-embed/main/screenshots/after.jpg)

## Quick Start

1. Install dependencies:
   ```bash
   npm install
   ```
2. Create `proxy-config.json` or set `PROXY_URLS` environment variable
3. Run:
   ```bash
   npm start
   ```

### Monitoring Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health status with server statistics |
| `GET /lb-stats` | Detailed load balancer statistics |

Example response from `/lb-stats`:
```json
{
  "algorithm": "round-robin",
  "healthyServers": 2,
  "totalServers": 3,
  "healthCheckInterval": 30000,
  "servers": [
    {
      "url": "https://proxy1.workers.dev",
      "healthy": true,
      "connections": 5,
      "totalRequests": 1000,
      "successRate": "99.50%",
      "responseTime": "45.23ms",
      "weight": 1,
      "failures": 1
    }
  ]
}
```

### How Failover Works

When a request fails, the proxy automatically retries on the next healthy server. Health checks run every 30 seconds (configurable) and unhealthy servers are automatically marked down. When a server recovers, it's automatically brought back online.