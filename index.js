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

const LB_ALGORITHM = process.env.LB_ALGORITHM || "round-robin";
const HEALTH_CHECK_INTERVAL = parseInt(process.env.HEALTH_CHECK_INTERVAL) || 30000;
const HEALTH_CHECK_TIMEOUT = parseInt(process.env.HEALTH_CHECK_TIMEOUT) || 10000;
const FAILURE_THRESHOLD = parseInt(process.env.FAILURE_THRESHOLD) || 3;

const weights = {};
if (process.env.PROXY_WEIGHTS) {
    process.env.PROXY_WEIGHTS.split(',').forEach(pair => {
        const [url, weight] = pair.split(':');
        weights[url] = parseInt(weight);
    });
}

class ServerPool {
    constructor(urls) {
        this.servers = urls.map(url => ({
            url: url,
            healthy: true,
            currentConnections: 0,
            totalRequests: 0,
            failures: 0,
            successRate: 1.0,
            weight: weights[url] || 1,
            lastCheck: Date.now(),
            responseTime: 0
        }));
        
        this.currentIndex = 0;
        this.currentWeight = 0;
        this.gcdWeight = this.calculateGCD();
        this.maxWeight = Math.max(...this.servers.map(s => s.weight));
    }
    
    calculateGCD() {
        const getGCD = (a, b) => b === 0 ? a : getGCD(b, a % b);
        return this.servers.map(s => s.weight).reduce((a, b) => getGCD(a, b));
    }
    
    getHealthyServers() {
        return this.servers.filter(s => s.healthy);
    }
    
    getAllServers() {
        return this.servers;
    }
    
    markHealthy(url) {
        const server = this.servers.find(s => s.url === url);
        if (server && !server.healthy) {
            server.healthy = true;
            server.failures = 0;
            console.log(`Server ${url} is BACK ONLINE`);
        }
    }
    
    markUnhealthy(url, reason) {
        const server = this.servers.find(s => s.url === url);
        if (server && server.healthy) {
            server.healthy = false;
            server.failures++;
            console.log(`Server ${url} is DOWN: ${reason}`);
        }
    }
    
    incrementConnections(url) {
        const server = this.servers.find(s => s.url === url);
        if (server) server.currentConnections++;
    }
    
    decrementConnections(url) {
        const server = this.servers.find(s => s.url === url);
        if (server) server.currentConnections--;
    }
    
    recordResponse(url, responseTime, success) {
        const server = this.servers.find(s => s.url === url);
        if (server) {
            server.totalRequests++;
            server.responseTime = responseTime;
            if (success) {
                server.successRate = (server.successRate * 0.9 + 1 * 0.1);
            } else {
                server.successRate = (server.successRate * 0.9 + 0 * 0.1);
            }
        }
    }
    
    getNextServer_roundRobin() {
        const healthyServers = this.getHealthyServers();
        if (healthyServers.length === 0) return null;
        
        this.currentIndex = (this.currentIndex + 1) % healthyServers.length;
        return healthyServers[this.currentIndex];
    }
    
    getNextServer_leastConnections() {
        const healthyServers = this.getHealthyServers();
        if (healthyServers.length === 0) return null;
        
        return healthyServers.reduce((min, server) => 
            server.currentConnections < min.currentConnections ? server : min
        );
    }
    
    getNextServer_weightedRoundRobin() {
        const healthyServers = this.getHealthyServers();
        if (healthyServers.length === 0) return null;
        
        while (true) {
            this.currentIndex = (this.currentIndex + 1) % healthyServers.length;
            if (this.currentIndex === 0) {
                this.currentWeight = this.currentWeight - this.gcdWeight;
                if (this.currentWeight <= 0) {
                    this.currentWeight = this.maxWeight;
                    if (this.currentWeight === 0) return null;
                }
            }
            
            if (healthyServers[this.currentIndex].weight >= this.currentWeight) {
                return healthyServers[this.currentIndex];
            }
        }
    }
    
    getNextServer_weightedLeastConnections() {
        const healthyServers = this.getHealthyServers();
        if (healthyServers.length === 0) return null;
        
        return healthyServers.reduce((best, server) => {
            const score = server.currentConnections / server.weight;
            const bestScore = best.currentConnections / best.weight;
            return score < bestScore ? server : best;
        });
    }
    
    getNextServer_ipHash(clientIp) {
        const healthyServers = this.getHealthyServers();
        if (healthyServers.length === 0) return null;
        
        let hash = 0;
        for (let i = 0; i < clientIp.length; i++) {
            hash = ((hash << 5) - hash) + clientIp.charCodeAt(i);
            hash |= 0;
        }
        
        const index = Math.abs(hash) % healthyServers.length;
        return healthyServers[index];
    }
    
    getNextServer_leastResponseTime() {
        const healthyServers = this.getHealthyServers();
        if (healthyServers.length === 0) return null;
        
        return healthyServers.reduce((fastest, server) => 
            server.responseTime < fastest.responseTime ? server : fastest
        );
    }
    
    getNextServer_random() {
        const healthyServers = this.getHealthyServers();
        if (healthyServers.length === 0) return null;
        
        const randomIndex = Math.floor(Math.random() * healthyServers.length);
        return healthyServers[randomIndex];
    }
    
    getNextServer(clientIp = null) {
        switch(LB_ALGORITHM) {
            case "least-connections":
                return this.getNextServer_leastConnections();
            case "weighted-round-robin":
                return this.getNextServer_weightedRoundRobin();
            case "weighted-least-connections":
                return this.getNextServer_weightedLeastConnections();
            case "ip-hash":
                return clientIp ? this.getNextServer_ipHash(clientIp) : this.getNextServer_roundRobin();
            case "least-response-time":
                return this.getNextServer_leastResponseTime();
            case "random":
                return this.getNextServer_random();
            case "round-robin":
            default:
                return this.getNextServer_roundRobin();
        }
    }
}

const serverPool = new ServerPool(proxyUrls);

const checkServerHealth = async (server) => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), HEALTH_CHECK_TIMEOUT);
    
    try {
        const startTime = Date.now();
        const response = await fetch(`${server.url}/health`, {
            method: 'GET', // Changed from HEAD to GET
            signal: controller.signal,
            headers: { 'User-Agent': 'LoadBalancer-HealthCheck/1.0' }
        });
        
        const responseTime = Date.now() - startTime;
        server.responseTime = responseTime;
        
        // Consider 2xx and 3xx as healthy (not just 2xx)
        if (response.status >= 200 && response.status < 400) {
            serverPool.markHealthy(server.url);
            return true;
        } else {
            throw new Error(`HTTP ${response.status}`);
        }
    } catch (error) {
        // Only mark as unhealthy if it's not a timeout (which might be transient)
        if (error.name !== 'AbortError') {
            serverPool.markUnhealthy(server.url, error.message);
        }
        return false;
    } finally {
        clearTimeout(timeoutId);
    }
};

const startHealthChecks = () => {
    console.log(`Starting active health checks every ${HEALTH_CHECK_INTERVAL}ms`);
    
    const performHealthChecks = async () => {
        const servers = serverPool.getAllServers();
        const results = await Promise.allSettled(
            servers.map(server => checkServerHealth(server))
        );
        
        const healthyCount = results.filter(r => r.value === true).length;
        console.log(`Health check complete: ${healthyCount}/${servers.length} servers healthy`);
    };
    
    performHealthChecks();
    
    setInterval(performHealthChecks, HEALTH_CHECK_INTERVAL);
};

const getStats = () => {
    const servers = serverPool.getAllServers();
    return {
        algorithm: LB_ALGORITHM,
        healthyServers: servers.filter(s => s.healthy).length,
        totalServers: servers.length,
        healthCheckInterval: HEALTH_CHECK_INTERVAL,
        servers: servers.map(s => ({
            url: s.url,
            healthy: s.healthy,
            connections: s.currentConnections,
            totalRequests: s.totalRequests,
            successRate: (s.successRate * 100).toFixed(2) + '%',
            responseTime: s.responseTime.toFixed(2) + 'ms',
            weight: s.weight,
            failures: s.failures
        }))
    };
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
    next();
});

app.get('/lb-stats', (req, res) => {
    res.json(getStats());
});

app.get('/health', (req, res) => {
    const stats = getStats();
    if (stats.healthyServers > 0) {
        res.status(200).json({ status: 'healthy', ...stats });
    } else {
        res.status(503).json({ status: 'unhealthy', ...stats });
    }
});

const isStreamingRequest = (req) => {
    const accept = req.headers['accept'] || '';
    return accept.includes('text/event-stream') || 
           accept.includes('application/stream+json') ||
           req.headers['x-stream'] === 'true';
};

const trackRequest = (req, res, targetServer, startTime) => {
    const responseTime = Date.now() - startTime;
    const success = res.statusCode < 400;
    serverPool.recordResponse(targetServer.url, responseTime, success);
    serverPool.decrementConnections(targetServer.url);
};

app.use("/", (req, res, next) => {
    let targetServer;
    
    if (LB_ALGORITHM === 'ip-hash') {
        targetServer = serverPool.getNextServer(req.clientIp);
    } else {
        targetServer = serverPool.getNextServer();
    }
    
    if (!targetServer) {
        return res.status(503).json({
            error: "No healthy servers available",
            message: "All proxy servers are currently down",
            timestamp: new Date().toISOString()
        });
    }
    
    serverPool.incrementConnections(targetServer.url);
    
    const startTime = Date.now();
    
    const proxy = createProxyMiddleware({
        target: targetServer.url,
        changeOrigin: true,
        pathRewrite: { "^/": "" },
        proxyTimeout: 10000, // 10 second proxy timeout
        timeout: 10000, // 10 second response timeout
        onProxyReq: (proxyReq, req) => {
            proxyReq.setHeader("X-Forwarded-For", req.clientIp);
            proxyReq.setHeader("X-Real-IP", req.clientIp);
            proxyReq.setHeader("X-Load-Balancer", LB_ALGORITHM);
            
            const headersToForward = ['user-agent', 'accept', 'accept-language', 'content-type', 
                                     'authorization', 'cookie', 'referer', 'origin', 'connection', 'cache-control'];
            
            headersToForward.forEach(header => {
                if (req.headers[header]) {
                    proxyReq.setHeader(header, req.headers[header]);
                }
            });
        },
        onProxyRes: (proxyRes, req, res) => {
            trackRequest(req, res, targetServer, startTime);
            
            proxyRes.headers['access-control-allow-origin'] = '*';
            proxyRes.headers['access-control-allow-methods'] = 'GET, POST, PUT, DELETE, OPTIONS';
            proxyRes.headers['access-control-allow-headers'] = 'Content-Type, Authorization, X-Requested-With, Accept, X-Stream';
            proxyRes.headers['access-control-expose-headers'] = '*';
            proxyRes.headers['x-load-balancer'] = LB_ALGORITHM;
            proxyRes.headers['x-backend-server'] = targetServer.url;
            
            if (isStreamingRequest(req)) {
                proxyRes.headers['cache-control'] = 'no-cache, no-transform, must-revalidate';
                proxyRes.headers['x-accel-buffering'] = 'no';
                proxyRes.headers['cf-cache-status'] = 'DYNAMIC';
                proxyRes.headers['connection'] = 'keep-alive';
                delete proxyRes.headers['content-length'];
            }
        },
        onError: (err, req, res) => {
            trackRequest(req, res, targetServer, startTime);
            
            // Only mark as unhealthy for certain types of errors
            const shouldMarkUnhealthy = !err.message.includes('ECONNRESET') && 
                                      !err.message.includes('socket hang up') &&
                                      !err.message.includes('timeout');
                                      
            if (shouldMarkUnhealthy) {
                serverPool.markUnhealthy(targetServer.url, err.message);
            }
            
            console.error(`Proxy error for ${targetServer.url}:`, err.message);
            
            const nextServer = serverPool.getNextServer();
            if (nextServer && nextServer.url !== targetServer.url) {
                console.log(`Retrying request on ${nextServer.url}`);
                
                const retryProxy = createProxyMiddleware({
                    target: nextServer.url,
                    changeOrigin: true,
                    pathRewrite: { "^/": "" },
                    proxyTimeout: 10000,
                    timeout: 10000,
                    onProxyReq: (proxyReq) => {
                        proxyReq.setHeader("X-Forwarded-For", req.clientIp);
                        proxyReq.setHeader("X-Retry-Count", "1");
                    },
                    onProxyRes: (proxyRes) => {
                        proxyRes.headers['x-retried'] = 'true';
                    }
                });
                
                return retryProxy(req, res, next);
            }
            
            res.status(502).json({
                error: "Proxy Error",
                message: err.message,
                failedServer: targetServer.url,
                timestamp: new Date().toISOString()
            });
        }
    });
    
    proxy(req, res, next);
});

app.options("*", (req, res) => {
    res.header('access-control-allow-origin', '*');
    res.header('access-control-allow-methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('access-control-allow-headers', 'Content-Type, Authorization, X-Requested-With, Accept, X-Stream');
    res.header('access-control-expose-headers', '*');
    res.sendStatus(200);
});

const port = process.env.PORT || 3000;

startHealthChecks();

app.listen(port, () => {
    console.log(`Load Balancer running on port ${port}`);
    console.log(`Algorithm: ${LB_ALGORITHM}`);
    console.log(`Backend Servers: ${proxyUrls.length}`);
    console.log(`Health Check Interval: ${HEALTH_CHECK_INTERVAL}ms`);
    console.log(`Stats Endpoint: GET /lb-stats`);
    console.log(`Health Endpoint: GET /health`);
});

process.on('SIGTERM', () => {
    console.log('Closing load balancer...');
    process.exit(0);
});