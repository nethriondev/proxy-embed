const express = require("express");
const { createProxyMiddleware } = require("http-proxy-middleware");

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
  
  if (req.headers['x-client-ip']) {
    return req.headers['x-client-ip'];
  }
  
  if (req.headers['x-cluster-client-ip']) {
    return req.headers['x-cluster-client-ip'];
  }
  
  if (req.headers['x-forwarded']) {
    const forwarded = req.headers['x-forwarded'].split(',')[0]?.trim();
    if (forwarded) return forwarded;
  }
  
  if (req.headers['forwarded']) {
    const match = req.headers['forwarded'].match(/for=([^;]+)/);
    if (match && match[1]) {
      return match[1].replace(/"/g, '');
    }
  }
  
  if (req.ip) {
    return req.ip;
  }
  
  if (req.connection && req.connection.remoteAddress) {
    return req.connection.remoteAddress;
  }
  
  if (req.socket && req.socket.remoteAddress) {
    return req.socket.remoteAddress;
  }
  
  if (req.connection && req.connection.socket && req.connection.socket.remoteAddress) {
    return req.connection.socket.remoteAddress;
  }
  
  return '0.0.0.0';
};

app.use((req, res, next) => {
  req.clientIp = getClientIp(req);
  next();
});

app.use(
  "/",
  createProxyMiddleware({
    target: "https://proxy-embed.nethriondev.workers.dev",
    changeOrigin: true,
    pathRewrite: { "^/": "" },
    onProxyReq: (proxyReq, req) => {
      proxyReq.setHeader("X-Forwarded-For", req.clientIp);
      proxyReq.setHeader("X-Real-IP", req.clientIp);
      proxyReq.setHeader("X-Client-IP", req.clientIp);
      proxyReq.setHeader("CF-Connecting-IP", req.clientIp);
      
      const existingForwardedFor = req.headers['x-forwarded-for'];
      if (existingForwardedFor && existingForwardedFor !== req.clientIp) {
        proxyReq.setHeader("X-Forwarded-For", `${existingForwardedFor}, ${req.clientIp}`);
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
      
      if (req.headers['referer']) {
        proxyReq.setHeader("Referer", req.headers['referer']);
      }
      
      if (req.headers['origin']) {
        proxyReq.setHeader("Origin", req.headers['origin']);
      }
      
      if (req.headers['cookie']) {
        proxyReq.setHeader("Cookie", req.headers['cookie']);
      }
      
      if (req.headers['authorization']) {
        proxyReq.setHeader("Authorization", req.headers['authorization']);
      }
    },
    onProxyRes: (proxyRes, req, res) => {
      proxyRes.headers['access-control-allow-origin'] = '*';
      proxyRes.headers['access-control-allow-headers'] = '*';
      proxyRes.headers['access-control-allow-methods'] = 'GET, POST, PUT, DELETE, OPTIONS';
      proxyRes.headers['access-control-allow-credentials'] = 'true';
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
  res.header('access-control-allow-headers', '*');
  res.header('access-control-allow-methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('access-control-allow-credentials', 'true');
  res.sendStatus(200);
});

app.get("/debug", (req, res) => {
  res.json({
    ip: req.clientIp,
    headers: req.headers,
    trustProxy: app.get('trust proxy')
  });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Proxy server running on port ${port}`);
});
