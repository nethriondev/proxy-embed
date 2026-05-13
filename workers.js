const ORIGIN_URLS = [
  'https://apiremake-production-4552.up.railway.app',
];

const BLOCKED_IPS = [
  '72.60.237.246'
];

const INTERNAL_PROXY_IPS = ["162.220.234.134"];

const RATE_LIMIT_WINDOW_MS = 10000;
const MAX_REQUESTS_PER_WINDOW = 500;
const BAN_THRESHOLD = 3;
const BAN_DURATION_MS = 300000;
const MAX_TRACKED_IPS = 10000;

let requestCount = 0;

const ipRequests = new Map();
const bannedIps = new Map();
const violationCounts = new Map();
const trustedIps = new Set();
const internalProxyIps = new Set(INTERNAL_PROXY_IPS);

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
  
  if (responseStatus !== 200 && responseStatus !== 206) {
    return 0;
  }
  
  if (hasRangeHeader) {
    return 3600;
  }
  
  if (pathname.startsWith('/api/') && !pathname.match(/\.(jpg|jpeg|png|gif|webp|bmp|svg|ico|mp4|webm|avi|mov|mkv|ts|m3u8|mpd|mp3|wav|ogg|m4a|flac|aac|m4s)$/i)) {
    return 0;
  }
  
  if (responseContentType.includes('application/json') ||
      responseContentType.includes('text/event-stream')) {
    return 0;
  }
  
  if (responseContentType.includes('text/html')) {
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
  
  return 43200;
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
      
      if (response.ok || response.status === 206) {
        return response;
      }

      if (response.status < 500) {
        return response;
      }

      lastError = new Error(`Origin ${originUrl} returned status ${response.status}`);
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError || new Error('All origins failed');
}

async function proxyRequestToOrigin(request, clientIP) {
  if (request.headers.get('upgrade')?.toLowerCase() === 'websocket') {
    try {
      const url = new URL(request.url);
      url.hostname = new URL(ORIGIN_URLS[0]).hostname;
      url.protocol = 'https:';
      url.port = '443';
      return fetch(url.toString(), request);
    } catch (error) {
      return new Response('WebSocket upgrade failed', { status: 502 });
    }
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

  if (request?.headers?.get('x-is-internal') === 'true') {
      request?.headers?.set('x-is-internal', 'true');
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

  resHeaders.set('Access-Control-Allow-Origin', '*');
  resHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  resHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Accept, X-Stream, Range');
  resHeaders.set('Access-Control-Expose-Headers', '*');

  const cacheTtl = getCacheTtl(url, contentType, !!rangeHeader, response.status);
  const shouldCache = cacheTtl > 0 && (response.status === 200 || response.status === 206);

  if (shouldCache) {
    resHeaders.set('Cache-Control', `public, max-age=${cacheTtl}, stale-while-revalidate=${Math.floor(cacheTtl/2)}`);
    resHeaders.set('CF-Cache-Status', 'MISS');
    resHeaders.set('X-Cache', 'MISS');
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