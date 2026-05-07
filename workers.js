const ORIGIN_URL = 'https://apiremake-production-441b.up.railway.app';

const DEFAULT_LIMIT = 1500;
const DEFAULT_WINDOW = 3600;
const BLOCK_DURATION = 15 * 60;

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

class RateLimiter {
  constructor() {
    this.blockedIPs = new Map();
    this.ipLimits = new Map();
  }

  isBlocked(ip) {
    if (this.blockedIPs.has(ip)) {
      if (Date.now() - this.blockedIPs.get(ip) < BLOCK_DURATION * 1000) {
        return true;
      }
      this.blockedIPs.delete(ip);
    }
    return false;
  }

  blockIP(ip) {
    this.blockedIPs.set(ip, Date.now());
  }

  checkLimit(ip) {
    let entry = this.ipLimits.get(ip);

    if (!entry || Date.now() > entry.reset * 1000) {
      entry = { limit: DEFAULT_LIMIT, reset: Math.floor(Date.now() / 1000) + DEFAULT_WINDOW, count: 0, mirrored: false };
      this.ipLimits.set(ip, entry);
    }

    entry.count++;

    if (entry.count > entry.limit) {
      this.blockIP(ip);
      return { blocked: true, count: entry.count, limit: entry.limit, reset: entry.reset, mirrored: entry.mirrored };
    }

    return { blocked: false, count: entry.count, limit: entry.limit, reset: entry.reset, mirrored: entry.mirrored };
  }

  mirrorOrigin(ip, originLimit, originReset) {
    if (!originLimit || !originReset) return;

    const reset = parseInt(originReset);
    const limit = parseInt(originLimit);
    if (isNaN(limit) || isNaN(reset)) return;

    const now = Math.floor(Date.now() / 1000);
    if (reset <= now) return;

    const existing = this.ipLimits.get(ip);
    if (existing) {
      existing.limit = limit;
      existing.reset = reset;
      existing.mirrored = true;
      if (existing.count > limit) {
        this.blockIP(ip);
      }
    }
  }

  cleanup() {
    const now = Date.now();
    for (const [ip, entry] of this.ipLimits) {
      if (now > entry.reset * 1000) {
        this.ipLimits.delete(ip);
      }
    }
    for (const [ip, time] of this.blockedIPs) {
      if (now - time > BLOCK_DURATION * 1000) {
        this.blockedIPs.delete(ip);
      }
    }
  }
}

const rateLimiter = new RateLimiter();
let requestCount = 0;

function getCacheTtl(url, responseContentType, hasRangeHeader) {
  const pathname = url.pathname.toLowerCase();
  
  if (hasRangeHeader) {
    return 3600;
  }
  
  if (responseContentType.includes('application/json')) {
    return 0;
  }
  
  if (pathname.startsWith('/api/') && !pathname.match(/\.(jpg|jpeg|png|gif|webp|bmp|svg|ico|mp4|webm|avi|mov|mkv|ts|m3u8|mpd|mp3|wav|ogg|m4a|flac|aac|m4s)$/i)) {
    return 0;
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
  
  if (responseContentType.includes('text/html') || 
      responseContentType.includes('application/xhtml+xml')) {
    return 3600;
  }
  
  return 43200;
}

function isVideoSegment(url) {
  const pathname = url.pathname.toLowerCase();
  return pathname.match(/\.(ts|m4s)$/i);
}

function isFirstRequest(url, headers) {
  const pathname = url.pathname.toLowerCase();
  
  if (pathname.endsWith('.m3u8') || pathname.endsWith('.mpd')) {
    return true;
  }
  
  if (pathname.match(/\.(mp4|webm|avi|mov|mkv)$/i) && !headers.get('range')) {
    return true;
  }
  
  return false;
}

async function proxyFetch(url, request, clientIP, rangeHeader) {
  const newHeaders = new Headers(request.headers);
  newHeaders.set('x-forwarded-for', clientIP);
  newHeaders.set('x-real-ip', clientIP);
  newHeaders.set('cf-connecting-ip', clientIP);

  const fetchUrl = new URL(url.toString());
  fetchUrl.hostname = new URL(ORIGIN_URL).hostname;
  fetchUrl.protocol = 'https:';
  fetchUrl.port = '443';

  const fetchOptions = {
    method: request.method,
    headers: newHeaders,
    cf: { polish: 'lossy', mirage: true }
  };

  if (rangeHeader) {
    fetchOptions.headers.set('Range', rangeHeader);
  }

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    fetchOptions.body = request.body;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 30000);

  try {
    const response = await fetch(fetchUrl.toString(), {
      ...fetchOptions,
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    return response;
  } catch (error) {
    clearTimeout(timeoutId);
    throw error;
  }
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Accept, X-Stream, Range",
          "Access-Control-Max-Age": "86400",
        }
      });
    }

    if (++requestCount % 100 === 0) {
      rateLimiter.cleanup();
    }

    const clientIP = getClientIp(request);
    const url = new URL(request.url);
    const rangeHeader = request.headers.get('range');
    if (rateLimiter.isBlocked(clientIP)) {
      return new Response(null, { status: 444 });
    }

    const rateResult = rateLimiter.checkLimit(clientIP);
    if (rateResult.blocked) {
      return new Response(null, { status: 444 });
    }

    const cacheKey = new Request(
      rangeHeader ? `${url.toString()}|${rangeHeader}` : url.toString(),
      request
    );

    if (request.method === 'GET') {
      const cache = caches.default;
      const cachedResponse = await cache.match(cacheKey);

      if (cachedResponse) {
        const cachedHeaders = new Headers(cachedResponse.headers);
        cachedHeaders.set('CF-Cache-Status', 'HIT');
        cachedHeaders.set('X-Cache', 'HIT');
        cachedHeaders.set('Access-Control-Allow-Origin', '*');
        cachedHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        cachedHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Accept, X-Stream, Range');
        cachedHeaders.set('ratelimit-limit', String(rateResult.limit));
        cachedHeaders.set('ratelimit-remaining', String(Math.max(0, rateResult.limit - rateResult.count)));
        cachedHeaders.set('ratelimit-reset', String(rateResult.reset));
        cachedHeaders.set('Cache-Control', 'private, max-age=0, must-revalidate');

        return new Response(cachedResponse.body, {
          status: cachedResponse.status,
          statusText: cachedResponse.statusText,
          headers: cachedHeaders
        });
      }
    }

    let response;
    try {
      response = await proxyFetch(url, request, clientIP, rangeHeader);
    } catch (error) {
      return new Response('Origin server error', { status: 502 });
    }

    const originLimit = response.headers.get('ratelimit-limit');
    const originReset = response.headers.get('ratelimit-reset');
    rateLimiter.mirrorOrigin(clientIP, originLimit, originReset);

    const recheck = rateLimiter.ipLimits.get(clientIP);
    const limit = recheck ? recheck.limit : rateResult.limit;
    const reset = recheck ? recheck.reset : rateResult.reset;
    const count = recheck ? recheck.count : rateResult.count;

    const responseToCache = response.clone();
    const resHeaders = new Headers(response.headers);
    const contentType = response.headers.get('content-type') || '';

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
    resHeaders.set('ratelimit-limit', String(limit));
    resHeaders.set('ratelimit-remaining', String(Math.max(0, limit - count)));
    resHeaders.set('ratelimit-reset', String(reset));

    const cacheTtl = getCacheTtl(url, contentType, !!rangeHeader);
    const shouldCache = cacheTtl > 0 && (response.status === 200 || response.status === 206);

    if (shouldCache) {
      resHeaders.set('Cache-Control', `private, max-age=${cacheTtl}, stale-while-revalidate=${cacheTtl/2}`);
      resHeaders.set('CF-Cache-Status', 'MISS');
      resHeaders.set('X-Cache', 'MISS');

      if (request.method === 'GET') {
        ctx.waitUntil(
          (async () => {
            const cache = caches.default;
            const cacheKey = new Request(
              rangeHeader ? `${url.toString()}|${rangeHeader}` : url.toString(),
              request
            );
            const cachedResponse = new Response(responseToCache.body, {
              status: responseToCache.status,
              statusText: responseToCache.statusText,
              headers: resHeaders
            });
            await cache.put(cacheKey, cachedResponse);
          })()
        );
      }
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: resHeaders
    });
  }
};
