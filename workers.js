const ORIGIN_URLS = [
  'https://apiremake-production-7612.up.railway.app',
];

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
const pathRequestTimestamps = new Map();

const ATTACK_CONFIG = {
    RATE_THRESHOLD_PER_PATH: 500,
    CACHE_PUNISHMENT_TTL: 300
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

const recordPathRequest = (path) => {
    const now = Date.now();
    
    if (!pathRequestTimestamps.has(path)) {
        pathRequestTimestamps.set(path, []);
    }
    
    const timestamps = pathRequestTimestamps.get(path);
    timestamps.push(now);
    
    const cutoff = now - 2000;
    while (timestamps.length > 0 && timestamps[0] < cutoff) {
        timestamps.shift();
    }
    
    const ratePerSecond = timestamps.length / 2;
    
    if (ratePerSecond >= ATTACK_CONFIG.RATE_THRESHOLD_PER_PATH) {
        if (!pathsUnderAttack.has(path)) {
            pathsUnderAttack.set(path, {
                active: true,
                rate: ratePerSecond,
                triggeredAt: now
            });
            console.log(`ATTACK DETECTED on ${path} | Rate: ${ratePerSecond} req/sec - CACHE PUNISHMENT ACTIVATED (${ATTACK_CONFIG.CACHE_PUNISHMENT_TTL}s)`);
        }
    }
};

const isPathUnderAttack = (path) => {
    return pathsUnderAttack.has(path);
};

setInterval(() => {
    const now = Date.now();
    const cutoff = now - 5000;
    
    for (const [path, timestamps] of pathRequestTimestamps) {
        while (timestamps.length > 0 && timestamps[0] < cutoff) {
            timestamps.shift();
        }
        if (timestamps.length === 0) {
            pathRequestTimestamps.delete(path);
        }
    }
}, 5000);

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

function getCacheTtl(url, responseContentType, hasRangeHeader, responseStatus) {
  const pathname = url.pathname.toLowerCase();
  
  if (responseContentType.includes('application/json') && isPathUnderAttack(pathname)) {
    return ATTACK_CONFIG.CACHE_PUNISHMENT_TTL;
  }
  
  if (responseStatus < 200 || responseStatus >= 300) {
    return 0;
  }
  
  if (hasRangeHeader) {
    return 3600;
  }
  
  if (responseContentType.includes('text/html') || 
      responseContentType.includes('application/javascript') || 
      responseContentType.includes('text/css') || 
      responseContentType.includes('text/plain') || 
      responseContentType.includes('text/xml')) {
    return 3600;
  }
  
  if (pathname.endsWith('.m3u8') || 
      responseContentType.includes('application/vnd.apple.mpegurl') ||
      responseContentType.includes('application/x-mpegurl')) {
    return 43200;
  }
  
  if (pathname.endsWith('.mpd') || 
      responseContentType.includes('application/dash+xml')) {
    return 43200;
  }
  
  if (pathname.endsWith('.ts') || pathname.endsWith('.m4s')) {
    return 43200;
  }
  
  if (pathname.match(/\.(jpg|jpeg|png|gif|webp|bmp|svg|ico)$/i)) {
    return 43200;
  }
  
  if (pathname.match(/\.(mp3|wav|ogg|m4a|flac|aac)$/i)) {
    return 43200;
  }
  
  if (pathname.match(/\.(mp4|webm|avi|mov|mkv)$/i)) {
    return 43200;
  }
  
  return 0;
}

async function proxyFetch(url, request, clientIP, rangeHeader, noCache) {
  const newHeaders = new Headers(request.headers);
  newHeaders.set('x-forwarded-for', clientIP);
  newHeaders.set('x-real-ip', clientIP);
  newHeaders.set('cf-connecting-ip', clientIP);

  const cfSettings = { 
    polish: 'lossy', 
    mirage: true 
  };
  
  if (!noCache) {
    cfSettings.cacheEverything = false;
  }

  let lastErrorResponse = null;
  let lastError = null;

  for (const originUrl of ORIGIN_URLS) {
    const fetchUrl = new URL(url.toString());
    fetchUrl.hostname = new URL(originUrl).hostname;
    fetchUrl.protocol = 'https:';
    fetchUrl.port = '443';

    const fetchOptions = {
      method: request.method,
      headers: new Headers(newHeaders),
      cf: { ...cfSettings }
    };

    if (rangeHeader) {
      fetchOptions.headers.set('Range', rangeHeader);
    }

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      fetchOptions.body = request.body;
    }

    try {
      const response = await fetch(fetchUrl.toString(), fetchOptions);

      if (response.status > 500) {
        lastErrorResponse = response;
        continue;
      }

      return response;
    } catch (error) {
      lastError = error;
    }
  }

  if (lastErrorResponse) {
    return lastErrorResponse;
  }
  
  throw lastError || new Error('All origins failed');
}

async function proxyRequestToOrigin(request, clientIP) {
  if (request.headers.get('upgrade')?.toLowerCase() === 'websocket') {
    let lastError = null;
    
    for (const originUrl of ORIGIN_URLS) {
      try {
        const url = new URL(request.url);
        url.hostname = new URL(originUrl).hostname;
        url.protocol = 'https:';
        url.port = '443';
        return fetch(url.toString(), request);
      } catch (error) {
        lastError = error;
        continue;
      }
    }
    
    return new Response('WebSocket upgrade failed - all origins unreachable', { status: 502 });
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

  let response;
  try {
    response = await proxyFetch(url, request, clientIP, rangeHeader, noCache);
  } catch (error) {
    return new Response(error.message || 'Origin server error', {
      status: 502,
      headers: {
        'Content-Type': 'text/plain'
      }
    });
  }

  if (request.headers.get('x-is-internal') === 'true') {
    trustedIps.add(clientIP);
  }

  const contentType = response.headers.get('content-type') || '';
  const resHeaders = new Headers(response.headers);

  if (response.status === 206) {
    const contentRange = response.headers.get('content-range');
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

  const cacheTtl = getCacheTtl(url, contentType, !!rangeHeader, response.status);
  const shouldCache = cacheTtl > 0;

  if (shouldCache) {
    resHeaders.set('Cache-Control', `public, max-age=${cacheTtl}, stale-while-revalidate=${Math.floor(cacheTtl/2)}`);
    resHeaders.set('CF-Cache-Status', 'MISS');
    resHeaders.set('X-Cache', 'MISS');
  } else {
    resHeaders.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: resHeaders
  });
}

export default {
  async fetch(request, env, ctx) {
    try {
      requestCount++;
      if (requestCount % 100 === 0) cleanMaps();

      const clientIP = getClientIp(request);
      const requestPathname = new URL(request.url).pathname.toLowerCase();
      recordPathRequest(requestPathname);

      if (trustedIps.has(clientIP) || internalProxyIps.has(clientIP)) {
        return await proxyRequestToOrigin(request, clientIP);
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
          headers: {
            'Content-Type': 'text/plain'
          }
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

      const result = await proxyRequestToOrigin(request, clientIP);

      return result;
    } catch (error) {
      return new Response('Internal Server Error', { 
        status: 500,
        headers: {
          'Content-Type': 'text/plain'
        }
      });
    }
  }
};