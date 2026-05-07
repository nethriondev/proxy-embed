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
    const isStatic = url.pathname.match(/\.(jpg|jpeg|png|gif|webp|bmp|svg|ico|css|js)$/i);
    
    const cache = caches.default;
    const rateKey = `rate:${clientIP}`;
    const rateCache = await cache.match(rateKey);
    
    let rateData = { count: 0, reset: Math.floor(Date.now() / 1000) + 3600 };
    
    if (rateCache) {
      const cached = await rateCache.json();
      rateData = cached;
    }
    
    const now = Math.floor(Date.now() / 1000);
    
    if (now > rateData.reset) {
      rateData = { count: 0, reset: now + 3600 };
    }
    
    if (!isStatic) {
      rateData.count++;
    }
    
    const remaining = Math.max(0, 1500 - rateData.count);
    
    const rateResponse = new Response(JSON.stringify(rateData), {
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=60' }
    });
    ctx.waitUntil(cache.put(rateKey, rateResponse));
    
    if (rateData.count > 1500) {
      return new Response(null, { status: 444 });
    }
    
    const newHeaders = new Headers(request.headers);
    newHeaders.set('x-forwarded-for', clientIP);
    newHeaders.set('x-real-ip', clientIP);
    newHeaders.set('cf-connecting-ip', clientIP);
    
    const cacheKey = new Request(
      rangeHeader ? `${url.toString()}|${rangeHeader}` : url.toString(), 
      request
    );
    
    const cachedResponse = await cache.match(cacheKey);
    
    if (cachedResponse && !isStatic) {
      const cachedHeaders = new Headers(cachedResponse.headers);
      cachedHeaders.set('ratelimit-limit', '1500');
      cachedHeaders.set('ratelimit-remaining', String(remaining));
      cachedHeaders.set('ratelimit-reset', String(rateData.reset));
      cachedHeaders.set('Access-Control-Allow-Origin', '*');
      
      return new Response(cachedResponse.body, {
        status: cachedResponse.status,
        statusText: cachedResponse.statusText,
        headers: cachedHeaders
      });
    }
    
    const fetchUrl = new URL(request.url);
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
    
    try {
      const response = await fetch(fetchUrl.toString(), fetchOptions);
      
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
      resHeaders.set('ratelimit-limit', '1500');
      resHeaders.set('ratelimit-remaining', String(remaining));
      resHeaders.set('ratelimit-reset', String(rateData.reset));
      
      const responseToCache = response.clone();
      const cacheTtl = 3600;
      
      if (request.method === 'GET' && !isStatic) {
        const cachedRes = new Response(responseToCache.body, {
          status: responseToCache.status,
          statusText: responseToCache.statusText,
          headers: resHeaders
        });
        ctx.waitUntil(cache.put(cacheKey, cachedRes));
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