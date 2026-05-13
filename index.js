const express = require("express");
const { createProxyMiddleware } = require("http-proxy-middleware");
const fs = require("fs");

let proxyUrls = [];
let blockedIps = ['72.60.237.246'];
let internalProxyIps = ["162.220.234.134"];

try {
    const configPath = "./proxy-config.json";
    if (fs.existsSync(configPath)) {
        const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
        proxyUrls = config.proxyUrls;
        if (config.blockedIps) {
            blockedIps = config.blockedIps;
        }
        if (config.internalProxyIps) {
            internalProxyIps = config.internalProxyIps;
        }
    }
} catch (err) {
    console.log("No proxy-config.json found, checking env...");
}

if (proxyUrls.length === 0) {
    if (process.env.PROXY_URL) {
        proxyUrls = [process.env.PROXY_URL];
        console.log(`Using single proxy from PROXY_URL: ${process.env.PROXY_URL}`);
    } else if (process.env.PROXY_URLS) {
        try {
            proxyUrls = JSON.parse(process.env.PROXY_URLS);
            console.log(`Using multiple proxies from PROXY_URLS: ${proxyUrls.join(', ')}`);
        } catch (err) {
            console.error("Error parsing PROXY_URLS, falling back to default");
            proxyUrls = ["https://proxy-embed.nethriondev.workers.dev"];
        }
    }
}

if (proxyUrls.length === 0) {
    proxyUrls = ["https://proxy-embed.nethriondev.workers.dev"];
    console.log("Using default proxy");
}

if (process.env.BLOCKED_IPS) {
    try {
        const envBlocked = JSON.parse(process.env.BLOCKED_IPS);
        blockedIps.push(...envBlocked);
        console.log(`Loaded ${envBlocked.length} blocked IPs from environment`);
    } catch (err) {
        console.error("Error parsing BLOCKED_IPS env var, using defaults");
    }
}

if (process.env.INTERNAL_PROXY_IPS) {
    try {
        const envInternal = JSON.parse(process.env.INTERNAL_PROXY_IPS);
        internalProxyIps.push(...envInternal);
        console.log(`Loaded ${envInternal.length} internal proxy IPs from environment`);
    } catch (err) {
        console.error("Error parsing INTERNAL_PROXY_IPS env var");
    }
}

const internalProxyIpSet = new Set(internalProxyIps);

let currentProxyIndex = 0;

const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 10000;
const MAX_REQUESTS_PER_WINDOW = parseInt(process.env.MAX_REQUESTS_PER_WINDOW) || 500;
const MAX_CONCURRENT_PER_IP = parseInt(process.env.MAX_CONCURRENT_PER_IP) || 100;
const BAN_THRESHOLD = parseInt(process.env.BAN_THRESHOLD) || 3;
const BAN_DURATION_MS = parseInt(process.env.BAN_DURATION_MS) || 300000;
const MAX_TRACKED_IPS = parseInt(process.env.MAX_TRACKED_IPS) || 10000;

const ipRequests = new Map();
const ipConcurrent = new Map();
const bannedIps = new Map();
const violationCounts = new Map();
const trustedIps = new Set();

const recordViolation = (ip) => {
    const count = (violationCounts.get(ip) || 0) + 1;
    violationCounts.set(ip, count);
    if (count >= BAN_THRESHOLD) {
        console.log(`Auto-banning IP ${ip} for ${BAN_DURATION_MS}ms`);
        bannedIps.set(ip, Date.now() + BAN_DURATION_MS);
        violationCounts.delete(ip);
    }
};

const isBanned = (ip) => {
    if (!bannedIps.has(ip)) return false;
    const until = bannedIps.get(ip);
    if (Date.now() > until) {
        bannedIps.delete(ip);
        return false;
    }
    return true;
};

const cleanMaps = () => {
    const now = Date.now();
    const cutoff = now - RATE_LIMIT_WINDOW_MS;
    for (const [ip, until] of bannedIps) {
        if (now > until) bannedIps.delete(ip);
    }
    for (const [ip, timestamps] of ipRequests) {
        while (timestamps.length > 0 && timestamps[0] < cutoff) timestamps.shift();
        if (timestamps.length === 0) {
            ipRequests.delete(ip);
            ipConcurrent.delete(ip);
            violationCounts.delete(ip);
        }
    }
    if (ipRequests.size > MAX_TRACKED_IPS) {
        const excess = [...ipRequests.entries()]
            .sort((a, b) => a[1][a[1].length - 1] - b[1][b[1].length - 1])
            .slice(0, ipRequests.size - MAX_TRACKED_IPS);
        for (const [ip] of excess) {
            ipRequests.delete(ip);
            ipConcurrent.delete(ip);
            violationCounts.delete(ip);
        }
    }
};

setInterval(cleanMaps, 15000);

const ensureCapacity = (ip) => {
    if (ipRequests.has(ip)) return;
    if (ipRequests.size >= MAX_TRACKED_IPS) {
        let oldest = null;
        let oldestTime = Infinity;
        for (const [entryIp, timestamps] of ipRequests) {
            const last = timestamps[timestamps.length - 1];
            if (last < oldestTime) {
                oldestTime = last;
                oldest = entryIp;
            }
        }
        if (oldest) {
            ipRequests.delete(oldest);
            ipConcurrent.delete(oldest);
            violationCounts.delete(oldest);
        }
    }
};

const app = express();

app.set('trust proxy', true);

app.disable('etag');

const getClientIp = (req) => {
  const forwardedHeader = req.headers['forwarded'];
  if (forwardedHeader) {
    const forMatch = forwardedHeader.match(/for=([^;]+)/);
    if (forMatch && forMatch[1]) {
      let ip = forMatch[1].replace(/^"|"$/g, '');
      ip = ip.replace(/^\[|\]$/g, '');
      if (ip && ip !== 'unknown') return ip;
    }
  }

  if (req.headers['x-vercel-forwarded-for']) {
    const ips = req.headers['x-vercel-forwarded-for'].split(',');
    const firstIp = ips[0]?.trim();
    if (firstIp) return firstIp;
  }

  if (req.headers['x-vercel-proxied-for']) {
    const ips = req.headers['x-vercel-proxied-for'].split(',');
    const firstIp = ips[0]?.trim();
    if (firstIp) return firstIp;
  }

  if (req.headers['x-forwarded-for']) {
    const ips = req.headers['x-forwarded-for'].split(',');
    const firstIp = ips[0]?.trim();
    if (firstIp) return firstIp;
  }

  if (req.headers['x-real-ip']) {
    return req.headers['x-real-ip'];
  }

  if (req.headers['cf-connecting-ip']) {
    return req.headers['cf-connecting-ip'];
  }
  
  if (req.clientIp) {
    return req.clientIp;
  }
  
  if (req.socket?.remoteAddress) {
    return req.socket.remoteAddress;
  }

  return req.ip || 'unknown';
};

app.use((req, res, next) => {
    req.clientIp = getClientIp(req);

    if (trustedIps.has(req.clientIp) || internalProxyIpSet.has(req.clientIp)) {
        next();
        return;
    }

    if (isBanned(req.clientIp)) {
        console.log(`Banned IP ${req.clientIp} auto-blocked`);
        req.socket.destroy();
        return;
    }

    if (blockedIps.includes(req.clientIp)) {
        console.log(`Blocked request from IP: ${req.clientIp}`);
        req.socket.destroy();
        return;
    }

    const now = Date.now();

    if (!ipRequests.has(req.clientIp)) {
        ensureCapacity(req.clientIp);
        ipRequests.set(req.clientIp, []);
    }
    const timestamps = ipRequests.get(req.clientIp);
    const windowStart = now - RATE_LIMIT_WINDOW_MS;
    while (timestamps.length > 0 && timestamps[0] < windowStart) {
        timestamps.shift();
    }
    if (timestamps.length >= MAX_REQUESTS_PER_WINDOW) {
        console.log(`Rate limit exceeded for ${req.clientIp}`);
        recordViolation(req.clientIp);
        req.socket.destroy();
        return;
    }
    timestamps.push(now);

    const concurrent = ipConcurrent.get(req.clientIp) || 0;
    if (concurrent >= MAX_CONCURRENT_PER_IP) {
        console.log(`Concurrent limit exceeded for ${req.clientIp}`);
        recordViolation(req.clientIp);
        req.socket.destroy();
        return;
    }
    ipConcurrent.set(req.clientIp, concurrent + 1);
    res.on('finish', () => {
        const c = ipConcurrent.get(req.clientIp) || 1;
        if (c <= 1) ipConcurrent.delete(req.clientIp);
        else ipConcurrent.set(req.clientIp, c - 1);
    });

    next();
});

const isStreamingRequest = (req) => {
    const accept = req.headers['accept'] || '';
    return accept.includes('text/event-stream') || 
           accept.includes('application/stream+json') ||
           req.headers['x-stream'] === 'true';
};

let currentProxy = proxyUrls[0];

const tryNextProxy = () => {
    if (proxyUrls.length > 1) {
        currentProxyIndex = (currentProxyIndex + 1) % proxyUrls.length;
        currentProxy = proxyUrls[currentProxyIndex];
        console.log(`Switching to proxy: ${currentProxy}`);
    } else {
        console.log(`Only one proxy available, cannot rotate: ${currentProxy}`);
    }
};

app.use(
    "/",
    createProxyMiddleware({
        router: (req) => {
            return currentProxy;
        },
        changeOrigin: true,
        pathRewrite: { "^/": "" },
        onProxyReq: (proxyReq, req) => {
            proxyReq.setHeader("X-Client-IP", req.clientIp);
            proxyReq.setHeader("X-Forwarded-For", req.clientIp);
            proxyReq.setHeader("X-Real-IP", req.clientIp);
            if (req?.headers?.['x-is-internal'] === 'true') {
                trustedIps.add(req.clientIp);
                proxyReq.setHeader("x-is-internal", "true");
            }

            if (req.headers['user-agent']) {
                proxyReq.setHeader("User-Agent", req.headers['user-agent']);
            }

            if (req.headers['accept']) {
                proxyReq.setHeader("Accept", req.headers['accept']);
            }

            if (req.headers['accept-language']) {
                proxyReq.setHeader("Accept-Language", req.headers['accept-language']);
            }

            if (req.headers['content-type']) {
                proxyReq.setHeader("Content-Type", req.headers['content-type']);
            }

            if (req.headers['authorization']) {
                proxyReq.setHeader("Authorization", req.headers['authorization']);
            }

            if (req.headers['cookie']) {
                proxyReq.setHeader("Cookie", req.headers['cookie']);
            }

            if (req.headers['referer']) {
                proxyReq.setHeader("Referer", req.headers['referer']);
            }

            if (req.headers['origin']) {
                proxyReq.setHeader("Origin", req.headers['origin']);
            }

            if (req.headers['connection']) {
                proxyReq.setHeader("Connection", req.headers['connection']);
            }

            if (req.headers['cache-control']) {
                proxyReq.setHeader("Cache-Control", req.headers['cache-control']);
            }
        },
        onProxyRes: (proxyRes, req, res) => {
            proxyRes.headers['access-control-allow-origin'] = '*';
            proxyRes.headers['access-control-allow-methods'] = 'GET, POST, PUT, DELETE, OPTIONS';
            proxyRes.headers['access-control-allow-headers'] = 'Content-Type, Authorization, X-Requested-With, Accept, X-Stream';
            proxyRes.headers['access-control-expose-headers'] = '*';
            
            if (isStreamingRequest(req)) {
                proxyRes.headers['cache-control'] = 'no-cache, no-transform, must-revalidate';
                proxyRes.headers['x-accel-buffering'] = 'no';
                proxyRes.headers['cf-cache-status'] = 'DYNAMIC';
                proxyRes.headers['connection'] = 'keep-alive';
                delete proxyRes.headers['content-length'];
            }
        },
        onError: (err, req, res) => {
            const statusCode = err.code === 'ECONNREFUSED' ? 502 :
                               err.code === 'ETIMEDOUT' ? 504 : 502;
            console.error(`Proxy error for ${currentProxy}:`, err.message, `(code: ${err.code || 'N/A'})`);
            
            if (proxyUrls.length > 1) {
                tryNextProxy();
                res.status(statusCode).json({
                    error: "Proxy Error",
                    message: err.message,
                    code: err.code || null,
                    nextProxy: currentProxy
                });
            } else {
                res.status(statusCode).json({
                    error: "Proxy Error",
                    message: err.message,
                    code: err.code || null,
                    note: "Only one proxy configured"
                });
            }
        }
    })
);

app.options("*", (req, res) => {
    res.header('access-control-allow-origin', '*');
    res.header('access-control-allow-methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('access-control-allow-headers', 'Content-Type, Authorization, X-Requested-With, Accept, X-Stream');
    res.header('access-control-expose-headers', '*');
    res.sendStatus(200);
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Proxy server running on port ${port}`);
    console.log(`Available proxies: ${proxyUrls.join(', ')}`);
    console.log(`Current proxy: ${currentProxy}`);
    console.log(`Proxy rotation: ${proxyUrls.length > 1 ? 'Enabled' : 'Disabled (single proxy only)'}`);
});