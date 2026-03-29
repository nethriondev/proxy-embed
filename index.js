const express = require("express");
const { createProxyMiddleware } = require("http-proxy-middleware");
const fs = require("fs");

let proxyUrls = [];

try {
    const configPath = "./proxy-config.json";
    if (fs.existsSync(configPath)) {
        const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
        proxyUrls = config.proxyUrls;
    }
} catch (err) {
    console.log("No proxy-config.json found, checking env...");
}

if (proxyUrls.length === 0 && process.env.PROXY_URLS) {
    proxyUrls = JSON.parse(process.env.PROXY_URLS);
}

if (proxyUrls.length === 0) {
    proxyUrls = ["https://proxy-embed.nethriondev.workers.dev"];
}

let currentProxyIndex = 0;

const app = express();

app.set('trust proxy', true);

const getClientIp = (req) => {
    const forwardedFor = req.headers['x-forwarded-for'];
    if (forwardedFor) {
        const ips = forwardedFor.split(',').map(ip => ip.trim());
        if (ips.length > 0 && ips[0]) {
            return ips[0];
        }
    }

    if (req.headers['cf-connecting-ip']) {
        return req.headers['cf-connecting-ip'];
    }

    if (req.headers['x-real-ip']) {
        return req.headers['x-real-ip'];
    }

    if (req.ip) {
        return req.ip;
    }

    if (req.socket && req.socket.remoteAddress) {
        return req.socket.remoteAddress;
    }

    return '0.0.0.0';
};

app.use((req, res, next) => {
    req.clientIp = getClientIp(req);
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
    currentProxyIndex = (currentProxyIndex + 1) % proxyUrls.length;
    currentProxy = proxyUrls[currentProxyIndex];
    console.log(`Switching to proxy: ${currentProxy}`);
};

app.use(
    "/",
    createProxyMiddleware({
        router: (req) => {
            return currentProxy;
        },
        changeOrigin: true,
        pathRewrite: { "^/": "" },
        proxyTimeout: 10000,
        timeout: 10000,
        onProxyReq: (proxyReq, req) => {
            proxyReq.setHeader("X-Forwarded-For", req.clientIp);
            proxyReq.setHeader("X-Real-IP", req.clientIp);

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
                proxyRes.headers['connection'] = 'keep-alive';
                delete proxyRes.headers['content-length'];
            }
        },
        onError: (err, req, res) => {
            console.error(`Proxy error for ${currentProxy}:`, err.message);
            tryNextProxy();
            
            res.status(500).json({
                error: "Proxy Error",
                message: err.message,
                nextProxy: currentProxy
            });
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
});