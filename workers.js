const ORIGIN_URL = 'https://apiremake-production-7612.up.railway.app';

const BLOCKED_IPS = [
  '72.60.237.246'
];

const INTERNAL_PROXY_IPS = ["162.220.234.134"];

const RATE_LIMIT_WINDOW_MS = 60000;
const MAX_REQUESTS_PER_WINDOW = 200;
const BAN_THRESHOLD = 3;
const BAN_DURATION_MS = 900000;
const MAX_TRACKED_IPS = 100000;

let requestCount = 0;

const ipRequests = new Map();
const bannedIps = new Map();
const violationCounts = new Map();
const trustedIps = new Set();
const internalProxyIps = new Set(INTERNAL_PROXY_IPS);

const pathsUnderAttack = new Map();
const ipPathTimestamps = new Map();

const ATTACK_CONFIG = {
    CACHE_PUNISHMENT_TTL: 300
};

const IP_PATH_ATTACK_THRESHOLD = 500;
const MAX_TRACKED_PATH_IPS = 50000;

const getTrackingWindowMs = () => {
    return ATTACK_CONFIG.CACHE_PUNISHMENT_TTL * 1000;
};

const isPathUnderAttack = (path) => {
    return pathsUnderAttack.has(path);
};

const ensurePathCapacity = (ip) => {
    if (ipPathTimestamps.has(ip)) return;
    if (ipPathTimestamps.size >= MAX_TRACKED_PATH_IPS) {
        let oldest = null;
        let oldestTime = Infinity;
        for (const [entryIp, pathTimestamps] of ipPathTimestamps) {
            let lastTime = 0;
            for (const timestamps of pathTimestamps.values()) {
                if (timestamps.length > 0) {
                    const t = timestamps[timestamps.length - 1];
                    if (t > lastTime) lastTime = t;
                }
            }
            if (lastTime < oldestTime) {
                oldestTime = lastTime;
                oldest = entryIp;
            }
        }
        if (oldest) {
            ipPathTimestamps.delete(oldest);
        }
    }
};

const recordPathRequest = (ip, path) => {
    const now = Date.now();
    const windowMs = getTrackingWindowMs();
    
    if (!ipPathTimestamps.has(ip)) {
        ensurePathCapacity(ip);
        ipPathTimestamps.set(ip, new Map());
    }
    
    const pathTimestamps = ipPathTimestamps.get(ip);
    
    if (!pathTimestamps.has(path)) {
        pathTimestamps.set(path, []);
    }
    
    const timestamps = pathTimestamps.get(path);
    timestamps.push(now);
    
    const cutoff = now - windowMs;
    while (timestamps.length > 0 && timestamps[0] < cutoff) {
        timestamps.shift();
    }
    
    const count = timestamps.length;
    
    if (count >= IP_PATH_ATTACK_THRESHOLD) {
        if (!pathsUnderAttack.has(path)) {
            pathsUnderAttack.set(path, {
                active: true,
                count: count,
                ip: ip,
                triggeredAt: now,
                windowMs: windowMs
            });
            console.log(`ATTACK DETECTED on ${path} | IP: ${ip} | Count: ${count} requests in ${windowMs/1000}s window - CACHE PUNISHMENT ACTIVATED (${ATTACK_CONFIG.CACHE_PUNISHMENT_TTL}s)`);
        } else {
            pathsUnderAttack.get(path).triggeredAt = now;
        }
    }
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
            violationCounts.delete(ip);
        }
    }
    if (ipRequests.size > MAX_TRACKED_IPS) {
        const excess = [...ipRequests.entries()]
            .sort((a, b) => a[1][a[1].length - 1] - b[1][b[1].length - 1])
            .slice(0, ipRequests.size - MAX_TRACKED_IPS);
        for (const [ip] of excess) {
            ipRequests.delete(ip);
            violationCounts.delete(ip);
        }
    }
    
    const punishCutoff = now - ATTACK_CONFIG.CACHE_PUNISHMENT_TTL * 1000;
    for (const [path, attack] of pathsUnderAttack) {
        if (attack.triggeredAt < punishCutoff) {
            console.log(`ATTACK DE-ESCALATED on ${path} - cache punishment expired`);
            pathsUnderAttack.delete(path);
        }
    }
    for (const [ip, pathTimestamps] of ipPathTimestamps) {
        for (const [path, timestamps] of pathTimestamps) {
            const cutoff2 = now - getTrackingWindowMs();
            while (timestamps.length > 0 && timestamps[0] < cutoff2) {
                timestamps.shift();
            }
            if (timestamps.length === 0) {
                pathTimestamps.delete(path);
            }
        }
        if (pathTimestamps.size === 0) {
            ipPathTimestamps.delete(ip);
        }
    }
    if (ipPathTimestamps.size > MAX_TRACKED_PATH_IPS) {
        const excess = [...ipPathTimestamps.entries()]
            .sort((a, b) => {
                const aLast = Math.max(...Array.from(a[1].values(), t => t[t.length - 1] || 0));
                const bLast = Math.max(...Array.from(b[1].values(), t => t[t.length - 1] || 0));
                return aLast - bLast;
            })
            .slice(0, ipPathTimestamps.size - MAX_TRACKED_PATH_IPS);
        for (const [ip] of excess) {
            ipPathTimestamps.delete(ip);
        }
    }
};

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
            violationCounts.delete(oldest);
        }
    }
};

function recordViolation(ip) {
  const count = (violationCounts.get(ip) || 0) + 1;
  violationCounts.set(ip, count);
  if (count >= BAN_THRESHOLD) {
    console.log(`Auto-banning IP ${ip} for ${BAN_DURATION_MS}ms`);
    bannedIps.set(ip, Date.now() + BAN_DURATION_MS);
    violationCounts.delete(ip);
  }
}

const getClientIp = (request) => {
  const clientIpHeader = request.headers.get('x-client-ip');
  if (clientIpHeader) {
    return clientIpHeader;
  }

  const forwardedHeader = request.headers.get('forwarded');
  if (forwardedHeader) {
    const forMatch = forwardedHeader.match(/for=([^;]+)/);
    if (forMatch && forMatch[1]) {
      let ip = forMatch[1].replace(/^"|"$/g, '');
      ip = ip.replace(/^\[|\]$/g, '');
      if (ip && ip !== 'unknown') return ip;
    }
  }

  const vercelForwardedFor = request.headers.get('x-vercel-forwarded-for');
  if (vercelForwardedFor) {
    const ips = vercelForwardedFor.split(',');
    const firstIp = ips[0]?.trim();
    if (firstIp) return firstIp;
  }

  const vercelProxiedFor = request.headers.get('x-vercel-proxied-for');
  if (vercelProxiedFor) {
    const ips = vercelProxiedFor.split(',');
    const firstIp = ips[0]?.trim();
    if (firstIp) return firstIp;
  }

  const xForwardedFor = request.headers.get('x-forwarded-for');
  if (xForwardedFor) {
    const ips = xForwardedFor.split(',');
    const firstIp = ips[0]?.trim();
    if (firstIp) return firstIp;
  }

  const xRealIp = request.headers.get('x-real-ip');
  if (xRealIp) {
    return xRealIp;
  }

  const cfConnectingIp = request.headers.get('cf-connecting-ip');
  if (cfConnectingIp) {
    return cfConnectingIp;
  }

  return 'unknown';
};

function getCacheTtl(url, responseContentType, hasRangeHeader, responseStatus, ext) {
  const pathname = url.pathname.toLowerCase();
  
  if (responseStatus < 200 || responseStatus >= 400) {
    return 0;
  }
  
  if (hasRangeHeader) {
    return 3600;
  }
  
  if (responseContentType.includes('application/json')) {
    if (isPathUnderAttack(pathname)) {
      return ATTACK_CONFIG.CACHE_PUNISHMENT_TTL;
    }
    return 0;
  }
  
  if (responseContentType.includes('text/event-stream')) {
    return 0;
  }
  
  if (responseContentType.includes('text/html') || 
      responseContentType.includes('application/javascript') || 
      responseContentType.includes('text/css') || 
      responseContentType.includes('text/plain') || 
      responseContentType.includes('text/xml')) {
    return 3600;
  }
  
  const effectivePath = ext ? pathname + ext.toLowerCase() : pathname;
  
  if (effectivePath.endsWith('.m3u8') || 
      responseContentType.includes('application/vnd.apple.mpegurl') ||
      responseContentType.includes('application/x-mpegurl')) {
    return 43200;
  }
  
  if (effectivePath.endsWith('.mpd') || 
      responseContentType.includes('application/dash+xml')) {
    return 43200;
  }
  
  if (effectivePath.endsWith('.ts') || effectivePath.endsWith('.m4s')) {
    return 43200;
  }
  
  if (effectivePath.match(/\.(jpg|jpeg|png|gif|webp|bmp|svg|ico)$/i)) {
    return 43200;
  }
  
  if (effectivePath.match(/\.(mp3|wav|ogg|m4a|flac|aac)$/i)) {
    return 43200;
  }
  
  if (effectivePath.match(/\.(mp4|webm|avi|mov|mkv)$/i)) {
    return 43200;
  }
  
  return 0;
}

async function proxyRequestToOrigin(request, clientIP, env, ctx) {
  if (request.headers.get('upgrade')?.toLowerCase() === 'websocket') {
    const url = new URL(request.url);
    url.hostname = new URL(ORIGIN_URL).hostname;
    url.protocol = 'https:';
    url.port = '443';
    return fetch(url.toString(), request);
  }

  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Accept, X-Stream, Range",
        "Access-Control-Max-Age": "86400",
      }
    });
  }

  const url = new URL(request.url);
  const rangeHeader = request.headers.get('range');
  
  const noCache = request.headers.get('cache-control')?.includes('no-cache') || 
                  request.headers.get('pragma') === 'no-cache';

  const cache = caches.default;
  const cacheKey = new Request(url.toString(), request);
  let cachedResponse = await cache.match(cacheKey);
  let fromCache = false;
  
  if (cachedResponse && !noCache) {
    fromCache = true;
  } else {
    const newHeaders = new Headers(request.headers);
    newHeaders.set('x-forwarded-for', clientIP);
    newHeaders.set('x-real-ip', clientIP);
    newHeaders.set('cf-connecting-ip', clientIP);
    newHeaders.set('x-is-internal', 'true');

    const fetchUrl = new URL(url.toString());
    fetchUrl.hostname = new URL(ORIGIN_URL).hostname;
    fetchUrl.protocol = 'https:';
    fetchUrl.port = '443';

    const fetchOptions = {
      method: request.method,
      headers: newHeaders,
      cf: { cacheEverything: true, polish: 'lossy', mirage: true }
    };

    if (rangeHeader) {
      fetchOptions.headers.set('Range', rangeHeader);
    }

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      fetchOptions.body = request.body;
    }

    try {
      cachedResponse = await fetch(fetchUrl.toString(), fetchOptions);
    } catch (error) {
      return new Response('Origin server error', {
        status: 502,
        headers: { 'Content-Type': 'text/plain' }
      });
    }
  }

  const contentType = cachedResponse.headers.get('content-type') || '';
  const resHeaders = new Headers(cachedResponse.headers);

  if (cachedResponse.status === 206) {
    const contentRange = cachedResponse.headers.get('content-range');
    if (contentRange) {
      resHeaders.set('content-range', contentRange);
    }
    resHeaders.set('accept-ranges', 'bytes');
  }

  resHeaders.delete('x-railway-edge');
  resHeaders.delete('x-railway-request-id');

  resHeaders.set('Access-Control-Allow-Origin', '*');
  resHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  resHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Accept, X-Stream, Range');
  resHeaders.set('Access-Control-Expose-Headers', '*');

  const ext = url.searchParams.get('ext') || undefined;
  const cacheTtl = getCacheTtl(url, contentType, !!rangeHeader, cachedResponse.status, ext);
  const shouldCache = cacheTtl > 0 && (cachedResponse.status === 200 || cachedResponse.status === 206);

  if (shouldCache) {
    resHeaders.set('Cache-Control', `public, max-age=${cacheTtl}, stale-while-revalidate=${Math.floor(cacheTtl/2)}`);
    resHeaders.set('CDN-Cache-Control', `public, max-age=${cacheTtl}`);
    resHeaders.set('X-Cache', fromCache ? 'HIT' : 'MISS');
    resHeaders.set('CF-Cache-Status', fromCache ? 'HIT' : 'MISS');
    resHeaders.set('Vary', 'Accept-Encoding');
  } else {
    resHeaders.set('Cache-Control', 'no-cache, no-store, must-revalidate');
    resHeaders.set('CDN-Cache-Control', 'no-cache, no-store, must-revalidate');
  }

  const responseBody = await cachedResponse.arrayBuffer();
  
  if (shouldCache && !noCache && !fromCache) {
    const newResponse = new Response(responseBody, {
      status: cachedResponse.status,
      statusText: cachedResponse.statusText,
      headers: resHeaders
    });
    
    ctx.waitUntil(cache.put(cacheKey, newResponse.clone()));
  }

  return new Response(responseBody, {
    status: cachedResponse.status,
    statusText: cachedResponse.statusText,
    headers: resHeaders
  });
}

setInterval(() => {
  cleanMaps();
}, 15000);

export default {
  async fetch(request, env, ctx) {
    try {
      requestCount++;
      if (requestCount % 100 === 0) cleanMaps();

      const clientIP = getClientIp(request);
      
      const url = new URL(request.url);
      recordPathRequest(clientIP, url.pathname);

      if (trustedIps.has(clientIP) || internalProxyIps.has(clientIP)) {
        return await proxyRequestToOrigin(request, clientIP, env, ctx);
      }

      if (bannedIps.has(clientIP)) {
        const until = bannedIps.get(clientIP);
        if (Date.now() < until) {
          return new Response('Too Many Requests', {
            status: 429,
            headers: { 'Content-Type': 'text/plain', 'Retry-After': '300' }
          });
        }
        bannedIps.delete(clientIP);
      }

      if (BLOCKED_IPS.includes(clientIP)) {
        return new Response('Forbidden', { 
          status: 403,
          headers: { 'Content-Type': 'text/plain' }
        });
      }

      const now = Date.now();

      if (!ipRequests.has(clientIP)) {
        ensureCapacity(clientIP);
        ipRequests.set(clientIP, []);
      }
      const timestamps = ipRequests.get(clientIP);
      const windowStart = now - RATE_LIMIT_WINDOW_MS;
      while (timestamps.length > 0 && timestamps[0] < windowStart) {
        timestamps.shift();
      }
      if (timestamps.length >= MAX_REQUESTS_PER_WINDOW) {
        recordViolation(clientIP);
        return new Response('Too Many Requests', {
          status: 429,
          headers: { 'Content-Type': 'text/plain', 'Retry-After': '300' }
        });
      }
      timestamps.push(now);

      const result = await proxyRequestToOrigin(request, clientIP, env, ctx);

      return result;
    } catch (error) {
      return new Response('Internal Server Error', { 
        status: 500,
        headers: { 'Content-Type': 'text/plain' }
      });
    }
  }
};