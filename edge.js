export const config = { runtime: 'edge' };

const PROXY_URLS = (() => {
  try {
    return process.env.PROXY_URLS ? JSON.parse(process.env.PROXY_URLS) : 
           process.env.PROXY_URL ? [process.env.PROXY_URL] : 
           ['https://proxy-embed.nethriondev.workers.dev'];
  } catch { return ['https://proxy-embed.nethriondev.workers.dev']; }
})();

const BLOCKED_IPS = (() => {
  const ips = ['72.60.237.246'];
  try {
    if (process.env.BLOCKED_IPS) ips.push(...JSON.parse(process.env.BLOCKED_IPS));
  } catch {}
  return ips;
})();

const INTERNAL_PROXY_IPS = new Set((() => {
  const ips = ['162.220.234.134'];
  try {
    if (process.env.INTERNAL_PROXY_IPS) ips.push(...JSON.parse(process.env.INTERNAL_PROXY_IPS));
  } catch {}
  return ips;
})());

const ATTACK_CONFIG = { CACHE_PUNISHMENT_TTL: 300 };
const IP_PATH_ATTACK_THRESHOLD = 500;
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 60000;
const MAX_REQUESTS_PER_WINDOW = parseInt(process.env.MAX_REQUESTS_PER_WINDOW) || 200;
const BAN_THRESHOLD = parseInt(process.env.BAN_THRESHOLD) || 3;
const BAN_DURATION_MS = parseInt(process.env.BAN_DURATION_MS) || 900000;

const ipRequests = new Map();
const bannedIps = new Map();
const violationCounts = new Map();
const trustedIps = new Set();
const pathsUnderAttack = new Map();
const ipPathTimestamps = new Map();
const responseCache = new Map();

const getTrackingWindowMs = () => ATTACK_CONFIG.CACHE_PUNISHMENT_TTL * 1000;

const isPathUnderAttack = (path) => pathsUnderAttack.has(path);

const getCacheTtl = (url, contentType, hasRangeHeader, statusCode, ext) => {
  const pathname = url.toLowerCase();
  
  if (contentType.includes('application/json') && isPathUnderAttack(pathname)) {
    return ATTACK_CONFIG.CACHE_PUNISHMENT_TTL;
  }
  if (statusCode < 200 || statusCode >= 400) return 0;
  if (hasRangeHeader) return 3600;
  if (contentType.includes('text/html') || contentType.includes('application/javascript') || 
      contentType.includes('text/css') || contentType.includes('text/plain') || 
      contentType.includes('text/xml')) return 3600;
  
  const effectivePath = ext ? pathname + ext.toLowerCase() : pathname;
  if (effectivePath.endsWith('.m3u8') || effectivePath.endsWith('.mpd') || 
      effectivePath.endsWith('.ts') || effectivePath.endsWith('.m4s')) return 43200;
  if (effectivePath.match(/\.(jpg|jpeg|png|gif|webp|bmp|svg|ico)$/i)) return 43200;
  if (effectivePath.match(/\.(mp3|wav|ogg|m4a|flac|aac)$/i)) return 43200;
  if (effectivePath.match(/\.(mp4|webm|avi|mov|mkv)$/i)) return 43200;
  
  return 0;
};

const getClientIp = (request) => {
  const forwarded = request.headers.get('forwarded');
  if (forwarded) {
    const match = forwarded.match(/for=([^;]+)/);
    if (match) return match[1].replace(/^"|"$/g, '').replace(/^\[|\]$/g, '');
  }
  return request.headers.get('x-vercel-forwarded-for')?.split(',')[0]?.trim() ||
         request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
         request.headers.get('x-real-ip') ||
         request.headers.get('cf-connecting-ip') ||
         'unknown';
};

const recordPathRequest = (ip, path) => {
  const now = Date.now();
  const windowMs = getTrackingWindowMs();
  
  if (!ipPathTimestamps.has(ip)) ipPathTimestamps.set(ip, new Map());
  const pathTimestamps = ipPathTimestamps.get(ip);
  if (!pathTimestamps.has(path)) pathTimestamps.set(path, []);
  
  const timestamps = pathTimestamps.get(path);
  timestamps.push(now);
  
  const cutoff = now - windowMs;
  while (timestamps.length > 0 && timestamps[0] < cutoff) timestamps.shift();
  
  if (timestamps.length >= IP_PATH_ATTACK_THRESHOLD && !pathsUnderAttack.has(path)) {
    pathsUnderAttack.set(path, { triggeredAt: now });
    console.log(`ATTACK DETECTED on ${path}`);
  }
};

const cleanMaps = () => {
  const now = Date.now();
  for (const [ip, until] of bannedIps) if (now > until) bannedIps.delete(ip);
  for (const [ip, timestamps] of ipRequests) {
    while (timestamps.length > 0 && timestamps[0] < now - RATE_LIMIT_WINDOW_MS) timestamps.shift();
    if (timestamps.length === 0) ipRequests.delete(ip);
  }
  for (const [path, attack] of pathsUnderAttack) {
    if (attack.triggeredAt < now - ATTACK_CONFIG.CACHE_PUNISHMENT_TTL * 1000) pathsUnderAttack.delete(path);
  }
  const cacheCutoff = now - 43200000;
  for (const [key, cached] of responseCache) {
    if (cached.expiry < now) responseCache.delete(key);
  }
};

setInterval(cleanMaps, 15000);

const isStreamingRequest = (request) => {
  const accept = request.headers.get('accept') || '';
  return accept.includes('text/event-stream') || 
         accept.includes('application/stream+json') ||
         request.headers.get('x-stream') === 'true';
};

export default async function handler(request) {
  try {
    cleanMaps();
    const clientIP = getClientIp(request);
    const url = new URL(request.url);
    const pathname = url.pathname;
    
    recordPathRequest(clientIP, pathname);
    
    if (trustedIps.has(clientIP) || INTERNAL_PROXY_IPS.has(clientIP)) {
      return await proxyRequest(request, clientIP, url);
    }
    
    if (bannedIps.has(clientIP)) {
      return new Response('Too Many Requests', { status: 429 });
    }
    
    if (BLOCKED_IPS.includes(clientIP)) {
      return new Response('Forbidden', { status: 403 });
    }
    
    const now = Date.now();
    if (!ipRequests.has(clientIP)) ipRequests.set(clientIP, []);
    const timestamps = ipRequests.get(clientIP);
    const windowStart = now - RATE_LIMIT_WINDOW_MS;
    while (timestamps.length > 0 && timestamps[0] < windowStart) timestamps.shift();
    
    if (timestamps.length >= MAX_REQUESTS_PER_WINDOW) {
      const count = (violationCounts.get(clientIP) || 0) + 1;
      violationCounts.set(clientIP, count);
      if (count >= BAN_THRESHOLD) {
        bannedIps.set(clientIP, now + BAN_DURATION_MS);
        violationCounts.delete(clientIP);
      }
      return new Response('Too Many Requests', { status: 429 });
    }
    timestamps.push(now);
    
    return await proxyRequest(request, clientIP, url);
  } catch (error) {
    return new Response('Internal Server Error', { status: 500 });
  }
}

async function proxyRequest(request, clientIP, url) {
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
  
  const cacheKey = `${request.method}:${url.pathname}${url.search}`;
  const cachedResponse = responseCache.get(cacheKey);
  const noCache = request.headers.get('cache-control')?.includes('no-cache') || 
                  request.headers.get('pragma') === 'no-cache';
  
  if (cachedResponse && !noCache && !isStreamingRequest(request)) {
    const isExpired = Date.now() > cachedResponse.expiry;
    if (!isExpired) {
      const headers = new Headers(cachedResponse.headers);
      headers.set('X-Cache', 'HIT');
      headers.set('CF-Cache-Status', 'HIT');
      return new Response(cachedResponse.body, {
        status: cachedResponse.statusCode,
        headers: headers
      });
    }
    responseCache.delete(cacheKey);
  }
  
  let currentProxyIndex = 0;
  let lastError = null;
  
  for (let i = 0; i < PROXY_URLS.length; i++) {
    const proxyUrl = PROXY_URLS[currentProxyIndex];
    currentProxyIndex = (currentProxyIndex + 1) % PROXY_URLS.length;
    
    try {
      const proxyHost = new URL(proxyUrl);
      const fetchUrl = new URL(url.toString());
      fetchUrl.hostname = proxyHost.hostname;
      fetchUrl.protocol = proxyHost.protocol;
      fetchUrl.port = proxyHost.port;
      
      const headers = new Headers(request.headers);
      headers.set('X-Client-IP', clientIP);
      headers.set('X-Forwarded-For', clientIP);
      headers.set('X-Real-IP', clientIP);
      headers.set('x-is-internal', 'true');
      
      const response = await fetch(fetchUrl.toString(), {
        method: request.method,
        headers: headers,
        body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined
      });
      
      const contentType = response.headers.get('content-type') || '';
      const ext = url.searchParams.get('ext') || undefined;
      const hasRangeHeader = !!request.headers.get('range');
      const cacheTtl = getCacheTtl(url.pathname, contentType, hasRangeHeader, response.status, ext);
      const shouldCache = cacheTtl > 0 && response.status === 200 && !isStreamingRequest(request);
      
      const responseHeaders = new Headers(response.headers);
      responseHeaders.delete('x-railway-edge');
      responseHeaders.delete('x-railway-request-id');
      responseHeaders.set('Access-Control-Allow-Origin', '*');
      responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      responseHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Accept, X-Stream, Range');
      responseHeaders.set('Access-Control-Expose-Headers', '*');
      
      if (shouldCache) {
        const cacheControl = `public, max-age=${cacheTtl}, stale-while-revalidate=${Math.floor(cacheTtl/2)}`;
        responseHeaders.set('Cache-Control', cacheControl);
        responseHeaders.set('CDN-Cache-Control', `public, max-age=${cacheTtl}`);
        responseHeaders.set('X-Cache', 'MISS');
        responseHeaders.set('CF-Cache-Status', 'MISS');
        responseHeaders.set('Vary', 'Accept-Encoding');
      } else {
        responseHeaders.set('Cache-Control', 'no-cache, no-store, must-revalidate');
        responseHeaders.set('CDN-Cache-Control', 'no-cache, no-store, must-revalidate');
      }
      
      const body = await response.arrayBuffer();
      
      if (shouldCache && !noCache) {
        responseCache.set(cacheKey, {
          body: body,
          headers: Object.fromEntries(responseHeaders),
          statusCode: response.status,
          expiry: Date.now() + (cacheTtl * 1000)
        });
      }
      
      return new Response(body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders
      });
    } catch (error) {
      lastError = error;
      continue;
    }
  }
  
  return new Response(lastError?.message || 'All proxies failed', { status: 502 });
}