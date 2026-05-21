const ORIGIN_URLS = [
  'https://segfault.nport.link',
  'https://anisekai.nport.link',
  'https://apiremake-production-c01a.up.railway.app'
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

const INTERNAL_PROXY_IPS = new Set(["162.220.234.134"]);

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
  response.headers.set("Cloudflare-CDN-Cache-Control", `public, max-age=${CACHE_CONFIG.ATTACK_PUNISHMENT_TTL}`);
  response.headers.delete("Vary");
  return response;
};

const pathsUnderAttack = new Map();
const ipPathTimestamps = new Map();
const IP_PATH_ATTACK_THRESHOLD = 500;
const ATTACK_WINDOW_MS = CACHE_CONFIG.ATTACK_PUNISHMENT_TTL * 1000;

const isPathUnderAttack = (path) => {
  return pathsUnderAttack.has(path);
};

const recordPathRequest = (ip, path) => {
  const now = Date.now();
  
  if (!ipPathTimestamps.has(ip)) {
    ipPathTimestamps.set(ip, new Map());
  }
  
  const pathTimestamps = ipPathTimestamps.get(ip);
  
  if (!pathTimestamps.has(path)) {
    pathTimestamps.set(path, []);
  }
  
  const timestamps = pathTimestamps.get(path);
  timestamps.push(now);
  
  const cutoff = now - ATTACK_WINDOW_MS;
  while (timestamps.length > 0 && timestamps[0] < cutoff) {
    timestamps.shift();
  }
  
  if (timestamps.length >= IP_PATH_ATTACK_THRESHOLD) {
    if (!pathsUnderAttack.has(path)) {
      pathsUnderAttack.set(path, {
        active: true,
        triggeredAt: now
      });
    } else {
      pathsUnderAttack.get(path).triggeredAt = now;
    }
  }
};

const cleanMaps = () => {
  const now = Date.now();
  const punishCutoff = now - ATTACK_WINDOW_MS;
  for (const [path, attack] of pathsUnderAttack) {
    if (attack.triggeredAt < punishCutoff) {
      pathsUnderAttack.delete(path);
    }
  }
  for (const [ip, pathTimestamps] of ipPathTimestamps) {
    for (const [path, timestamps] of pathTimestamps) {
      const cutoff = now - ATTACK_WINDOW_MS;
      while (timestamps.length > 0 && timestamps[0] < cutoff) {
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
};

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

  const vercelForwardedFor = request.headers.get('x-vercel-forwarded-for');
  if (vercelForwardedFor) {
    const ips = vercelForwardedFor.split(',');
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

async function tryOrigin(originUrl, targetUrl, fetchOptions) {
  const fetchUrl = new URL(targetUrl.toString());
  fetchUrl.hostname = new URL(originUrl).hostname;
  fetchUrl.protocol = 'https:';
  fetchUrl.port = '443';

  const response = await fetch(fetchUrl.toString(), fetchOptions);
  if (response.status < 500) {
    return response;
  }
  throw new Error(`${originUrl} returned ${response.status}`);
}

async function fetchFromFastestOrigin(url, fetchOptions) {
  const tunnelOrigins = ORIGIN_URLS.filter(o => !o.includes('railway.app'));
  const backupOrigins = ORIGIN_URLS.filter(o => o.includes('railway.app'));
  
  try {
    const promises = tunnelOrigins.map(origin => tryOrigin(origin, url, fetchOptions));
    return await Promise.any(promises);
  } catch {
    for (const origin of backupOrigins) {
      try {
        return await tryOrigin(origin, url, fetchOptions);
      } catch (e) {}
    }
    throw new Error('All origins failed');
  }
}

async function fetchWebSocketFromFastestOrigin(request) {
  const tunnelOrigins = ORIGIN_URLS.filter(o => !o.includes('railway.app'));
  const backupOrigins = ORIGIN_URLS.filter(o => o.includes('railway.app'));
  
  try {
    const promises = tunnelOrigins.map(async (origin) => {
      const wsUrl = new URL(request.url);
      wsUrl.hostname = new URL(origin).hostname;
      wsUrl.protocol = 'https:';
      wsUrl.port = '443';

      const wsHeaders = new Headers(request.headers);
      wsHeaders.delete('connection');
      wsHeaders.delete('upgrade');
      wsHeaders.delete('sec-websocket-key');
      wsHeaders.delete('sec-websocket-version');
      wsHeaders.delete('sec-websocket-extensions');
      wsHeaders.delete('sec-websocket-accept');

      const response = await fetch(wsUrl.toString(), {
        method: request.method,
        headers: wsHeaders,
        body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
        duplex: 'half'
      });
      if (response.status === 101 || response.status < 500) {
        return response;
      }
      throw new Error(`${origin} returned ${response.status}`);
    });
    return await Promise.any(promises);
  } catch {
    for (const origin of backupOrigins) {
      try {
        const wsUrl = new URL(request.url);
        wsUrl.hostname = new URL(origin).hostname;
        wsUrl.protocol = 'https:';
        wsUrl.port = '443';

        const wsHeaders = new Headers(request.headers);
        wsHeaders.delete('connection');
        wsHeaders.delete('upgrade');
        wsHeaders.delete('sec-websocket-key');
        wsHeaders.delete('sec-websocket-version');
        wsHeaders.delete('sec-websocket-extensions');
        wsHeaders.delete('sec-websocket-accept');

        const response = await fetch(wsUrl.toString(), {
          method: request.method,
          headers: wsHeaders,
          body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
          duplex: 'half'
        });
        if (response.status === 101 || response.status < 500) {
          return response;
        }
        throw new Error(`${origin} returned ${response.status}`);
      } catch (e) {}
    }
    throw new Error('All WebSocket origins failed');
  }
}

async function getCache() {
  if (typeof caches !== 'undefined' && typeof caches.open === 'function') {
    return await caches.open('proxy-cache');
  }
  return null;
}

async function proxyRequestToOrigin(request, clientIP, ctx) {
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

  const cache = await getCache();
  const cacheKeyOptions = { method: request.method };
  if (rangeHeader) {
    cacheKeyOptions.headers = { Range: rangeHeader };
  }
  const cacheKey = new Request(url.toString(), cacheKeyOptions);
  let cachedResponse = null;
  let fromCache = false;
  
  if (cache) {
    cachedResponse = await cache.match(cacheKey);
  }
  
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
      cf: {
        cacheTtl: 3600,
        cacheEverything: true,
        polish: 'lossy',
        mirage: true
      }
    };

    if (rangeHeader) {
      fetchOptions.headers.set('Range', rangeHeader);
    }

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      fetchOptions.body = request.body;
      fetchOptions.duplex = 'half';
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
      const warmUrl = new URL(url.toString());
      warmUrl.hostname = new URL(originUrl).hostname;
      warmUrl.protocol = 'https:';
      warmUrl.port = '443';
      const promise = fetch(warmUrl.toString(), { method: 'HEAD' }).catch(() => {});
      if (ctx && ctx.waitUntil) {
        ctx.waitUntil(promise);
      }
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
  if (shouldCache) {
    resHeaders.set('Cache-Control', `public, max-age=${cacheTtl}, stale-while-revalidate=${Math.floor(cacheTtl/2)}`);
    resHeaders.set('CDN-Cache-Control', `public, max-age=${cacheTtl}`);
    resHeaders.set('Cloudflare-CDN-Cache-Control', `public, max-age=${cacheTtl}`);
    resHeaders.set('X-Cache', fromCache ? 'HIT' : 'MISS');
    resHeaders.set('Cache-Tag', `path-${pathname.replace(/\//g, '-')}`);
    resHeaders.delete('Vary');
  } else {
    resHeaders.set('Cache-Control', 'no-cache, no-store, must-revalidate');
    resHeaders.set('CDN-Cache-Control', 'no-cache, no-store, must-revalidate');
    resHeaders.set('Cloudflare-CDN-Cache-Control', 'no-cache, no-store, must-revalidate');
    resHeaders.delete('Vary');
  }

  const responseForCache = shouldCache && !noCache && !fromCache ? cachedResponse.clone() : null;

  const finalResponse = new Response(cachedResponse.body, {
    status: cachedResponse.status,
    statusText: cachedResponse.statusText,
    headers: resHeaders
  });

  if (responseForCache && cache) {
    const cacheHeaders = new Headers(resHeaders);
    cacheHeaders.set('Cache-Control', `max-age=${cacheTtl}`);
    cacheHeaders.set('CDN-Cache-Control', `max-age=${cacheTtl}`);
    cacheHeaders.set('Cloudflare-CDN-Cache-Control', `max-age=${cacheTtl}`);

    const cacheResponse = new Response(responseForCache.body, {
      status: responseForCache.status,
      statusText: responseForCache.statusText,
      headers: cacheHeaders
    });

    const putPromise = cache.put(cacheKey, cacheResponse).catch((e) => console.error('cache.put failed:', e));
    if (ctx && ctx.waitUntil) {
      ctx.waitUntil(putPromise);
    } else {
      await putPromise;
    }
  }

  return finalResponse;
}

async function handler(request, env, ctx) {
  try {
    const clientIP = getClientIp(request);
    const url = new URL(request.url);
    
    recordPathRequest(clientIP, url.pathname);
    
    if (INTERNAL_PROXY_IPS.has(clientIP)) {
      return await proxyRequestToOrigin(request, clientIP, ctx);
    }

    if (BLOCKED_IPS.includes(clientIP)) {
      return getSelfRedirectResponse(clientIP);
    }

    const result = await proxyRequestToOrigin(request, clientIP, ctx);
    
    if (ctx && ctx.waitUntil) {
      ctx.waitUntil(Promise.resolve(cleanMaps()));
    } else {
      cleanMaps();
    }
    
    return result;
  } catch (error) {
    console.error('Handler error:', error);
    return new Response('Internal Server Error', { 
      status: 500,
      headers: { 'Content-Type': 'text/plain' }
    });
  }
}

export default {
  fetch(request, env, ctx) {
    return handler(request, env, ctx);
  }
};