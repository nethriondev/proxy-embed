const express = require("express");
const { createProxyMiddleware } = require("http-proxy-middleware");

const worker_proxy = "https://proxy-embed.nethriondev.workers.dev";

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
app.use(
    "/",
    createProxyMiddleware({
        target: worker_proxy,
        changeOrigin: true,
        pathRewrite: { "^/": "" },
        proxyTimeout: 0, // No timeout for streaming
        timeout: 0, // No timeout
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
            res.status(500).json({
                error: "Proxy Error",
                message: err.message
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
    console.log(`Target: ${worker_proxy}`);
});