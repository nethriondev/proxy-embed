export const config = {
  runtime: 'edge'
};

const ORIGIN_URLS = [
  'https://proxy-embed.nethriondev.workers.dev'
];

const SERVERLESS_DOMAINS = [
  'onrender.com',
  'vercel.app',
  'netlify.app',
  'fly.dev',
  'deno.dev'
];

const BLOCKED_IPS = [
  '72.60.237.246'
];

const INTERNAL_PROXY_IPS = ["162.220.234.134"];

const RATE_LIMIT_WINDOW_MS = 60000;
const MAX_REQUESTS_PER_WINDOW = 200;
const BAN_THRESHOLD = 3;
const BAN_DURATION_MS = 900000;

const CACHE_CONFIG = {
  SEGMENT_TTL: 86400,
  PARTIAL_TTL: 86400,
  FULL_TTL: 604800,
  MANIFEST_TTL: 43200,
  ATTACK_PUNISHMENT_TTL: 300
};

const getSelfRedirectResponse = (attackerIP) => {
  const response = Response.redirect(`http://${attackerIP}/`, 307);
  response.headers.set("x-skid-ip", `${attackerIP} - hina ng ddos mo tanga!`);
  response.headers.set("Cache-Control", `public, max-age=${CACHE_CONFIG.ATTACK_PUNISHMENT_TTL}`);
  response.headers.set("CDN-Cache-Control", `public, max-age=${CACHE_CONFIG.ATTACK_PUNISHMENT_TTL}`);
  response.headers.delete("Vary");
  return response;
};

const ipRequests = new Map();
const bannedIps = new Map();
const violationCounts = new Map();
const trustedIps = new Set();
const internalProxyIps = new Set(INTERNAL_PROXY_IPS);

const pathsUnderAttack = new Map();
const ipPathTimestamps = new Map();

const IP_PATH_ATTACK_THRESHOLD = 500;

const getTrackingWindowMs = () => {
  return CACHE_CONFIG.ATTACK_PUNISHMENT_TTL * 1000;
};

const isPathUnderAttack = (path) => {
  return pathsUnderAttack.has(path);
};

const recordPathRequest = (ip, path) => {
  const now = Date.now();
  const windowMs = getTrackingWindowMs();
  
  if (!ipPathTimestamps.has(ip)) {
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
    } else {
      pathsUnderAttack.get(path).triggeredAt = now;
    }
  }
};

function cleanMaps() {
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
  
  const punishCutoff = now - CACHE_CONFIG.ATTACK_PUNISHMENT_TTL * 1000;
  for (const [path, attack] of pathsUnderAttack) {
    if (attack.triggeredAt < punishCutoff) {
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
}

function recordViolation(ip) {
  const count = (violationCounts.get(ip) || 0) + 1;
  violationCounts.set(ip, count);
  if (count >= BAN_THRESHOLD) {
    bannedIps.set(ip, Date.now() + BAN_DURATION_MS);
    violationCounts.delete(ip);
  }
}

const getClientIp = (request) => {
  const forwardedHeader = request.headers.get('forwarded');
  if (forwardedHeader) {
    const forMatch = forwardedHeader.match(/for=([^;]+)/);
    if (forMatch && forMatch[1]) {
      let ip = forMatch[1].replace(/^"|"$/g, '');
      ip = ip.replace(/^\[|\]$/g, '');
      if (ip && ip !== 'unknown') return ip;
    }
  }

  const xForwardedFor = request.headers.get('x-forwarded-for');
  if (xForwardedFor) {
    const ips = xForwardedFor.split(',');
    const firstIp = ips[0]?.trim();
    if (firstIp) return firstIp;
  }

  const xRealIp = request.headers.get('x-real-ip');
  if (xRealIp) return xRealIp;

  const cfConnectingIp = request.headers.get('cf-connecting-ip');
  if (cfConnectingIp) return cfConnectingIp;

  return 'unknown';
};

function getCacheTtl(url, responseContentType, hasRangeHeader, responseStatus, contentLength, ext) {
  const pathname = url.pathname.toLowerCase();
  
  if (responseStatus < 200 || responseStatus >= 400) {
    return 0;
  }
  
  if (responseContentType.includes('application/json')) {
    if (isPathUnderAttack(pathname)) {
      return CACHE_CONFIG.ATTACK_PUNISHMENT_TTL;
    }
    return 0;
  }
  
  if (responseContentType.includes('text/event-stream')) {
    return 0;
  }
  
  const effectivePath = ext ? pathname + ext.toLowerCase() : pathname;
  
  if (effectivePath.match(/\.(ts|m4s)$/i)) {
    return CACHE_CONFIG.SEGMENT_TTL;
  }
  
  if (effectivePath.match(/\.(mp4|webm|avi|mov|mkv)$/i)) {
    if (contentLength > 10 * 1024 * 1024) {
      return 0;
    }
    if (hasRangeHeader) {
      return CACHE_CONFIG.PARTIAL_TTL;
    }
    return CACHE_CONFIG.FULL_TTL;
  }
  
  if (effectivePath.match(/\.(mp3|wav|ogg|m4a|flac|aac)$/i)) {
    if (contentLength > 10 * 1024 * 1024) {
      return 0;
    }
    if (hasRangeHeader) {
      return CACHE_CONFIG.PARTIAL_TTL;
    }
    return CACHE_CONFIG.FULL_TTL;
  }
  
  if (effectivePath.endsWith('.m3u8') || 
      effectivePath.endsWith('.mpd') ||
      responseContentType.includes('application/vnd.apple.mpegurl') ||
      responseContentType.includes('application/x-mpegurl') ||
      responseContentType.includes('application/dash+xml')) {
    return CACHE_CONFIG.MANIFEST_TTL;
  }
  
  if (effectivePath.match(/\.(jpg|jpeg|png|gif|webp|bmp|svg|ico)$/i)) {
    return CACHE_CONFIG.FULL_TTL;
  }
  
  if (responseContentType.includes('text/html') || 
      responseContentType.includes('application/javascript') || 
      responseContentType.includes('text/css') || 
      responseContentType.includes('text/plain') || 
      responseContentType.includes('text/xml')) {
    return 3600;
  }
  
  return 0;
}

async function fetchFromFastestOrigin(url, fetchOptions) {
  const promises = ORIGIN_URLS.map(async (originUrl) => {
    const fetchUrl = new URL(url.toString());
    fetchUrl.hostname = new URL(originUrl).hostname;
    fetchUrl.protocol = 'https:';
    fetchUrl.port = '443';

    const response = await fetch(fetchUrl.toString(), fetchOptions);
    if (response.status < 500) {
      return response;
    }
    throw new Error(`${originUrl} returned ${response.status}`);
  });

  try {
    return await Promise.any(promises);
  } catch {
    throw new Error('All origins failed');
  }
}

async function fetchWebSocketFromFastestOrigin(request) {
  const promises = ORIGIN_URLS.map(async (originUrl) => {
    const url = new URL(request.url);
    url.hostname = new URL(originUrl).hostname;
    url.protocol = 'https:';
    url.port = '443';

    const response = await fetch(url.toString(), request);
    if (response.status === 101 || response.status < 500) {
      return response;
    }
    throw new Error(`${originUrl} returned ${response.status}`);
  });

  try {
    return await Promise.any(promises);
  } catch {
    throw new Error('All WebSocket origins failed');
  }
}

async function proxyRequestToOrigin(request, clientIP) {
  if (request.headers.get('upgrade')?.toLowerCase() === 'websocket') {
    try {
      return await fetchWebSocketFromFastestOrigin(request);
    } catch {
      return new Response('WebSocket connection failed', {
        status: 502,
        headers: { 'Content-Type': 'text/plain' }
      });
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
  const pathname = url.pathname.toLowerCase();
  
  const rangeHeader = request.headers.get('range');
  const noCache = request.headers.get('cache-control')?.includes('no-cache') || 
                  request.headers.get('pragma') === 'no-cache';

  const cache = caches.default;
  const cacheKeyOptions = { method: request.method };
  if (rangeHeader) {
    cacheKeyOptions.headers = { Range: rangeHeader };
  }
  const cacheKey = new Request(url.toString(), cacheKeyOptions);
  let cachedResponse = await cache.match(cacheKey);
  let fromCache = false;
  
  if (cachedResponse && !noCache) {
    fromCache = true;
  } else {
    const newHeaders = new Headers(request.headers);
    newHeaders.set('x-forwarded-for', clientIP);
    newHeaders.set('x-real-ip', clientIP);
    newHeaders.set('cf-connecting-ip', clientIP);

    const fetchOptions = {
      method: request.method,
      headers: newHeaders,
    };

    if (rangeHeader) {
      fetchOptions.headers.set('Range', rangeHeader);
    }

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      fetchOptions.body = request.body;
    }

    try {
      cachedResponse = await fetchFromFastestOrigin(url, fetchOptions);
    } catch {
      return new Response('Origin server error', {
        status: 502,
        headers: { 'Content-Type': 'text/plain' }
      });
    }

    for (const originUrl of ORIGIN_URLS) {
      if (!SERVERLESS_DOMAINS.some(d => originUrl.includes(d))) continue;
      fetch(originUrl, { method: 'HEAD' }).catch(() => {});
    }
  }

  const contentType = cachedResponse.headers.get('content-type') || '';
  const resHeaders = new Headers(cachedResponse.headers);
  const contentLength = parseInt(cachedResponse.headers.get('content-length') || '0');

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
  const cacheTtl = getCacheTtl(url, contentType, !!rangeHeader, cachedResponse.status, contentLength, ext);
  const shouldCache = cacheTtl > 0 && (cachedResponse.status === 200 || cachedResponse.status === 206);
  const isMedia = pathname.match(/\.(ts|m4s|mp4|webm|avi|mov|mkv|mp3|wav|ogg|m4a|flac|aac|m3u8|mpd)$/i);

  if (shouldCache) {
    if (isPathUnderAttack(pathname) && contentType.includes('application/json')) {
      resHeaders.set('Cache-Control', `public, max-age=${CACHE_CONFIG.ATTACK_PUNISHMENT_TTL}, stale-while-revalidate=0`);
    } else {
      resHeaders.set('Cache-Control', `public, max-age=${cacheTtl}, stale-while-revalidate=${Math.floor(cacheTtl/2)}`);
    }
    resHeaders.set('CDN-Cache-Control', `public, max-age=${cacheTtl}`);
    resHeaders.set('X-Cache', fromCache ? 'HIT' : 'MISS');
    resHeaders.set('CF-Cache-Status', fromCache ? 'HIT' : 'MISS');
    resHeaders.delete('Vary');
  } else {
    resHeaders.set('Cache-Control', 'no-cache, no-store, must-revalidate');
    resHeaders.set('CDN-Cache-Control', 'no-cache, no-store, must-revalidate');
    resHeaders.delete('Vary');
  }

  if (isMedia && shouldCache) {
    if (!fromCache) {
      const newResponse = new Response(cachedResponse.body, {
        status: cachedResponse.status,
        statusText: cachedResponse.statusText,
        headers: resHeaders
      });
      await cache.put(cacheKey, newResponse.clone());
      return newResponse;
    }
    return new Response(cachedResponse.body, {
      status: cachedResponse.status,
      statusText: cachedResponse.statusText,
      headers: resHeaders
    });
  }

  const responseBody = await cachedResponse.arrayBuffer();
  
  if (shouldCache && !noCache && !fromCache) {
    const newResponse = new Response(responseBody, {
      status: cachedResponse.status,
      statusText: cachedResponse.statusText,
      headers: resHeaders
    });
    await cache.put(cacheKey, newResponse.clone());
  }

  return new Response(responseBody, {
    status: cachedResponse.status,
    statusText: cachedResponse.statusText,
    headers: resHeaders
  });
}

export default async function middleware(request) {
  try {
    const clientIP = getClientIp(request);
    
    const url = new URL(request.url);
    
    recordPathRequest(clientIP, url.pathname);
    
    if (trustedIps.has(clientIP) || internalProxyIps.has(clientIP)) {
      return await proxyRequestToOrigin(request, clientIP);
    }

    if (bannedIps.has(clientIP)) {
      const until = bannedIps.get(clientIP);
      if (Date.now() < until) {
        return getSelfRedirectResponse(clientIP);
      }
      bannedIps.delete(clientIP);
    }

    if (BLOCKED_IPS.includes(clientIP)) {
      return getSelfRedirectResponse(clientIP);
    }

    const now = Date.now();

    if (!ipRequests.has(clientIP)) {
      ipRequests.set(clientIP, []);
    }
    const timestamps = ipRequests.get(clientIP);
    const windowStart = now - RATE_LIMIT_WINDOW_MS;
    while (timestamps.length > 0 && timestamps[0] < windowStart) {
      timestamps.shift();
    }
    if (timestamps.length >= MAX_REQUESTS_PER_WINDOW) {
      recordViolation(clientIP);
      return getSelfRedirectResponse(clientIP);
    }
    timestamps.push(now);

    const result = await proxyRequestToOrigin(request, clientIP);
    cleanMaps();
    return result;
  } catch (error) {
    return new Response('Internal Server Error', { 
      status: 500,
      headers: { 'Content-Type': 'text/plain' }
    });
  }
}