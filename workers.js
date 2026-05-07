const ORIGIN_URL = 'https://apiremake-production-441b.up.railway.app';
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
  constructor(env) {
    this.kv = env.RATE_LIMIT_KV;
    this.blockDuration = 15 * 60;
    this.blockedIPs = new Map();
  }

  async isBlocked(ip) {
    if (this.blockedIPs.has(ip)) {
      const blockTime = this.blockedIPs.get(ip);
      if (Date.now() - blockTime < this.blockDuration * 1000) {
        return true;
      }
      this.blockedIPs.delete(ip);
    }

    try {
      const blockedData = await this.kv.get(`blocked:${ip}`);
      if (blockedData) {
        const blockInfo = JSON.parse(blockedData);
        if (Date.now() - blockInfo.blockedAt < this.blockDuration * 1000) {
          this.blockedIPs.set(ip, blockInfo.blockedAt);
          return true;
        } else {
          await this.kv.delete(`blocked:${ip}`);
          await this.kv.delete(`ratelimit:${ip}`);
          await this.kv.delete(`ratelimit_config:${ip}`);
        }
      }
    } catch (error) {}
    return false;
  }

  async blockIP(ip) {
    const now = Date.now();
    this.blockedIPs.set(ip, now);
    await this.kv.put(`blocked:${ip}`, JSON.stringify({
      blockedAt: now
    }), { expirationTtl: this.blockDuration });
  }

  async getRateLimitConfig(ip) {
    const key = `ratelimit_config:${ip}`;
    const now = Math.floor(Date.now() / 1000);
    
    try {
      const config = await this.kv.get(key, { type: "json" });
      
      if (config && config.reset > now) {
        return config;
      }
    } catch (error) {}
    
    return null;
  }

  async setRateLimitConfig(ip, limit, reset) {
    const key = `ratelimit_config:${ip}`;
    const now = Math.floor(Date.now() / 1000);
    const windowSeconds = reset - now;
    
    const config = {
      limit: limit,
      reset: reset,
      windowSeconds: windowSeconds
    };
    
    await this.kv.put(key, JSON.stringify(config), { expirationTtl: windowSeconds + 300 });
    return config;
  }

  async checkLimit(ip, limit, windowSeconds) {
    try {
      const now = Date.now();
      const key = `ratelimit:${ip}`;
      const data = await this.kv.get(key);
      const windowMs = windowSeconds * 1000;
      
      let requestData;
      if (data) {
        requestData = JSON.parse(data);
        if (now - requestData.windowStart > windowMs) {
          requestData = { windowStart: now, count: 1 };
        } else {
          requestData.count++;
        }
      } else {
        requestData = { windowStart: now, count: 1 };
      }

      if (requestData.count > limit) {
        await this.blockIP(ip);
        return { blocked: true, count: requestData.count };
      }

      await this.kv.put(key, JSON.stringify(requestData), { 
        expirationTtl: Math.ceil(windowMs / 1000) 
      });

      return { blocked: false, count: requestData.count, remaining: limit - requestData.count };
    } catch (error) {
      return { blocked: false, count: 0, error: true, remaining: limit };
    }
  }
}

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

    const clientIP = getClientIp(request);
    const url = new URL(request.url);
    const rangeHeader = request.headers.get('range');
    const rateLimiter = new RateLimiter(env);
    
    const isBlockedPromise = rateLimiter.isBlocked(clientIP);
    const timeoutPromise = new Promise(resolve => setTimeout(() => resolve(false), 100));
    const isBlocked = await Promise.race([isBlockedPromise, timeoutPromise]);
    
    if (isBlocked) {
      return new Response(null, { status: 444 });
    }
    
    const isManifestOrFirst = isFirstRequest(url, request.headers);
    const isSegment = isVideoSegment(url);
    
    let limitConfig = await rateLimiter.getRateLimitConfig(clientIP);
    
    const newHeaders = new Headers(request.headers);
    newHeaders.set('x-forwarded-for', clientIP);
    newHeaders.set('x-real-ip', clientIP);
    newHeaders.set('cf-connecting-ip', clientIP);
    
    async function tryFetch(rangeHeader) {
      const fetchUrl = new URL(request.url);
      fetchUrl.hostname = new URL(ORIGIN_URL).hostname;
      fetchUrl.protocol = 'https:';
      fetchUrl.port = '443';
      
      const fetchOptions = {
        method: request.method,
        headers: newHeaders,
        cf: {
          polish: 'lossy',
          mirage: true,
        }
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
    
    if (!limitConfig) {
      try {
        const response = await tryFetch(rangeHeader);
        
        const originRateLimit = response.headers.get('ratelimit-limit');
        const originRateReset = response.headers.get('ratelimit-reset');
        
        let limit = 1500;
        let reset = Math.floor(Date.now() / 1000) + 3600;
        
        if (originRateLimit && originRateReset) {
          limit = parseInt(originRateLimit);
          reset = parseInt(originRateReset);
        }
        
        limitConfig = await rateLimiter.setRateLimitConfig(clientIP, limit, reset);
        
        const rateResult = await rateLimiter.checkLimit(clientIP, limit, limitConfig.windowSeconds);
        
        if (rateResult.blocked) {
          return new Response(null, { status: 444 });
        }
        
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
        
        const cacheTtl = getCacheTtl(url, contentType, !!rangeHeader);
        
        resHeaders.set('Access-Control-Allow-Origin', '*');
        resHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        resHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Accept, X-Stream, Range');
        resHeaders.set('Access-Control-Expose-Headers', '*');
        resHeaders.set('ratelimit-limit', String(limit));
        resHeaders.set('ratelimit-remaining', String(rateResult.remaining));
        resHeaders.set('ratelimit-reset', String(reset));
        
        const shouldCache = cacheTtl > 0 && 
                           (response.status === 200 || response.status === 206);
        
        if (shouldCache && request.method === 'GET') {
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
          ctx.waitUntil(cache.put(cacheKey, cachedResponse));
        }
        
        return new Response(response.body, {
          status: response.status,
          statusText: response.statusText,
          headers: resHeaders
        });
        
      } catch (error) {
        const now = Math.floor(Date.now() / 1000);
        limitConfig = await rateLimiter.setRateLimitConfig(clientIP, 1500, now + 3600);
        
        const rateResult = await rateLimiter.checkLimit(clientIP, 1500, 3600);
        
        if (rateResult.blocked) {
          return new Response(null, { status: 444 });
        }
        
        try {
          const response = await tryFetch(rangeHeader);
          
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
          
          const cacheTtl = getCacheTtl(url, contentType, !!rangeHeader);
          
          resHeaders.set('Access-Control-Allow-Origin', '*');
          resHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
          resHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Accept, X-Stream, Range');
          resHeaders.set('Access-Control-Expose-Headers', '*');
          resHeaders.set('ratelimit-limit', String(1500));
          resHeaders.set('ratelimit-remaining', String(rateResult.remaining));
          resHeaders.set('ratelimit-reset', String(now + 3600));
          
          const shouldCache = cacheTtl > 0 && 
                             (response.status === 200 || response.status === 206);
          
          if (shouldCache && request.method === 'GET') {
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
            ctx.waitUntil(cache.put(cacheKey, cachedResponse));
          }
          
          return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: resHeaders
          });
          
        } catch (fallbackError) {
          return new Response('Origin server error', { status: 502 });
        }
      }
    }
    
    let cachedResponse = null;
    const cacheKey = new Request(
      rangeHeader ? `${url.toString()}|${rangeHeader}` : url.toString(), 
      request
    );
    
    if (request.method === 'GET') {
      const cache = caches.default;
      cachedResponse = await cache.match(cacheKey);
    }
    
    const rateResult = await rateLimiter.checkLimit(clientIP, limitConfig.limit, limitConfig.windowSeconds);
    
    if (rateResult.blocked) {
      return new Response(null, { status: 444 });
    }
    
    if (cachedResponse && !isSegment) {
      const cachedHeaders = new Headers(cachedResponse.headers);
      cachedHeaders.set('CF-Cache-Status', 'HIT');
      cachedHeaders.set('X-Cache', 'HIT');
      cachedHeaders.set('Access-Control-Allow-Origin', '*');
      cachedHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      cachedHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Accept, X-Stream, Range');
      cachedHeaders.set('Access-Control-Expose-Headers', '*');
      cachedHeaders.set('ratelimit-limit', String(limitConfig.limit));
      cachedHeaders.set('ratelimit-remaining', String(rateResult.remaining));
      cachedHeaders.set('ratelimit-reset', String(limitConfig.reset));
      
      return new Response(cachedResponse.body, {
        status: cachedResponse.status,
        statusText: cachedResponse.statusText,
        headers: cachedHeaders
      });
    }
    
    try {
      const response = await tryFetch(rangeHeader);
      
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
      
      const cacheTtl = getCacheTtl(url, contentType, !!rangeHeader);
      
      resHeaders.set('Access-Control-Allow-Origin', '*');
      resHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      resHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Accept, X-Stream, Range');
      resHeaders.set('Access-Control-Expose-Headers', '*');
      resHeaders.set('ratelimit-limit', String(limitConfig.limit));
      resHeaders.set('ratelimit-remaining', String(rateResult.remaining));
      resHeaders.set('ratelimit-reset', String(limitConfig.reset));
      
      const shouldCache = cacheTtl > 0 && 
                         (response.status === 200 || response.status === 206);
      
      if (shouldCache && request.method === 'GET' && !isSegment) {
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
        ctx.waitUntil(cache.put(cacheKey, cachedResponse));
      }
      
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: resHeaders
      });
      
    } catch (error) {
      return new Response('Origin server error', { status: 502 });
    }
  }
};