const express = require("express");
const { createProxyMiddleware } = require("http-proxy-middleware");
const fs = require("fs");
const http = require("http");
const https = require("https");

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

let currentProxyIndex = 0;

const app = express();

app.set('trust proxy', true);
app.disable('x-powered-by');

const getClientIp = (req) => {
    if (req.headers['x-forwarded-for']) {
        const ips = req.headers['x-forwarded-for'].split(',');
        return ips[0].trim();
    }
    
    if (req.headers['cf-connecting-ip']) {
        return req.headers['cf-connecting-ip'];
    }
    
    if (req.headers['x-real-ip']) {
        return req.headers['x-real-ip'];
    }
    
    if (req.headers['x-forwarded-host']) {
        return req.headers['x-forwarded-host'].split(',')[0].trim();
    }
    
    return req.ip || req.socket?.remoteAddress || '0.0.0.0';
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
    if (proxyUrls.length > 1) {
        currentProxyIndex = (currentProxyIndex + 1) % proxyUrls.length;
        currentProxy = proxyUrls[currentProxyIndex];
        console.log(`Switching to proxy: ${currentProxy}`);
    } else {
        console.log(`Only one proxy available, cannot rotate: ${currentProxy}`);
    }
};

const agentConfig = {
    keepAlive: true,
    keepAliveMsecs: 30000,
    maxSockets: 50,
    maxFreeSockets: 10,
    scheduling: 'fifo',
    noDelay: true,
};

const httpAgent = new http.Agent(agentConfig);
const httpsAgent = new https.Agent(agentConfig);

app.use(
    "/",
    createProxyMiddleware({
        router: (req) => currentProxy,
        ws: true,
        changeOrigin: true,
        agent: (req) => currentProxy.startsWith('https://') ? httpsAgent : httpAgent,
        pathRewrite: { "^/": "" },
        xfwd: true,
        
        onProxyReq: (proxyReq, req) => {
            proxyReq.setHeader("X-Forwarded-For", req.clientIp);
            proxyReq.setHeader("X-Real-IP", req.clientIp);
            proxyReq.setHeader("X-Forwarded-Host", req.headers.host || '');

            const headers = [
                'user-agent', 'accept', 'accept-language', 'content-type',
                'authorization', 'cookie', 'referer', 'origin', 'connection',
                'cache-control', 'accept-encoding', 'x-request-id', 'x-correlation-id'
            ];
            
            headers.forEach(header => {
                if (req.headers[header]) {
                    proxyReq.setHeader(header, req.headers[header]);
                }
            });
        },
        
        onProxyRes: (proxyRes, req, res) => {
            proxyRes.headers['access-control-allow-origin'] = '*';
            proxyRes.headers['access-control-allow-methods'] = 'GET, POST, PUT, DELETE, OPTIONS';
            proxyRes.headers['access-control-allow-headers'] = '*';
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
            
            if (proxyUrls.length > 1) {
                tryNextProxy();
                res.status(500).json({
                    error: "Proxy Error",
                    message: err.message,
                    nextProxy: currentProxy
                });
            } else {
                res.status(500).json({
                    error: "Proxy Error",
                    message: err.message,
                    note: "Only one proxy configured"
                });
            }
        }
    })
);

app.options("*", (req, res) => {
    res.header('access-control-allow-origin', '*');
    res.header('access-control-allow-methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('access-control-allow-headers', '*');
    res.header('access-control-expose-headers', '*');
    res.sendStatus(204);
});

const port = process.env.PORT || 3000;
const server = app.listen(port, () => {
    console.log(`Proxy server running on port ${port}`);
    console.log(`Available proxies: ${proxyUrls.join(', ')}`);
    console.log(`Current proxy: ${currentProxy}`);
    console.log(`Proxy rotation: ${proxyUrls.length > 1 ? 'Enabled' : 'Disabled (single proxy only)'}`);
});

process.on('SIGTERM', () => {
    server.close(() => {
        httpAgent.destroy();
        httpsAgent.destroy();
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    server.close(() => {
        httpAgent.destroy();
        httpsAgent.destroy();
        process.exit(0);
    });
});