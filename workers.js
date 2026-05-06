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

function isCacheableMedia(request) {
  const url = new URL(request.url);
  const pathname = url.pathname.toLowerCase();
  
  const mediaExtensions = [
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.svg', '.ico',
    '.mp4', '.webm', '.avi', '.mov', '.mkv', '.flv', '.ts', '.m3u8', '.mpd',
    '.mp3', '.wav', '.ogg', '.m4a', '.flac', '.aac', '.m4s'
  ];
  
  if (mediaExtensions.some(ext => pathname.endsWith(ext))) {
    return true;
  }
  
  const acceptHeader = request.headers.get('accept') || '';
  if (acceptHeader.includes('image/') || 
      acceptHeader.includes('video/') || 
      acceptHeader.includes('audio/')) {
    return true;
  }
  
  if (pathname.includes('/media') || pathname.includes('/api/stream')) {
    return true;
  }
  
  return false;
}

function getCacheTtl(url, request) {
  const pathname = url.pathname.toLowerCase();
  const contentType = request.headers.get('content-type') || '';
  
  if (pathname.endsWith('.m3u8') || 
      contentType.includes('application/vnd.apple.mpegurl') ||
      contentType.includes('application/x-mpegurl')) {
    return 300;
  }
  
  if (pathname.endsWith('.mpd') || 
      contentType.includes('application/dash+xml')) {
    return 300;
  }
  
  if (pathname.endsWith('.ts') || pathname.endsWith('.m4s')) {
    return 86400;
  }
  
  if (pathname.match(/\.(jpg|jpeg|png|gif|webp|bmp|svg|ico)$/i)) {
    return 604800;
  }
  
  if (pathname.match(/\.(mp3|wav|ogg|m4a|flac|aac)$/i)) {
    return 86400;
  }
  
  if (pathname.match(/\.(mp4|webm|avi|mov|mkv)$/i)) {
    return 21600;
  }
  
  if (pathname.includes('/media') || pathname.includes('/api/stream')) {
    const expireParam = url.searchParams.get('expire');
    if (expireParam === 'never') return 2592000;
    if (expireParam) {
      const match = expireParam.match(/^(\d+)([hdm])$/);
      if (match) {
        const value = parseInt(match[1]);
        const unit = match[2];
        if (unit === 'h') return value * 3600;
        if (unit === 'd') return value * 86400;
        if (unit === 'm') return value * 60;
      }
    }
    if (pathname.includes('m3u8') || pathname.includes('mpd')) {
      return 300;
    }
    return 3600;
  }
  
  return 3600;
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
    
    const newHeaders = new Headers(request.headers);
    newHeaders.set('x-forwarded-for', clientIP);
    newHeaders.set('x-real-ip', clientIP);
    newHeaders.set('cf-connecting-ip', clientIP);
    
    const acceptHeader = request.headers.get('accept') || '';
    const isStreamingRequest = acceptHeader.includes('text/event-stream') || 
                              acceptHeader.includes('application/stream+json') ||
                              request.headers.get('x-stream') === 'true';
    
    const isMedia = isCacheableMedia(request);
    const cacheTtl = isMedia ? getCacheTtl(url, request) : 0;
    const cacheKey = new Request(url.toString(), request);
    let response = null;
    
    if (isMedia && cacheTtl > 0 && request.method === 'GET') {
      const cache = caches.default;
      const cachedResponse = await cache.match(cacheKey);
      
      if (cachedResponse) {
        const cachedHeaders = new Headers(cachedResponse.headers);
        cachedHeaders.set('CF-Cache-Status', 'HIT');
        cachedHeaders.set('X-Cache', 'HIT');
        cachedHeaders.set('Access-Control-Allow-Origin', '*');
        cachedHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        cachedHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Accept, X-Stream, Range');
        
        return new Response(cachedResponse.body, {
          status: cachedResponse.status,
          statusText: cachedResponse.statusText,
          headers: cachedHeaders
        });
      }
    }
    
    async function tryFetch(hostname) {
      const fetchUrl = new URL(request.url);
      fetchUrl.hostname = hostname;
      fetchUrl.protocol = 'https:';
      fetchUrl.port = '443';
      
      const fetchOptions = {
        method: request.method,
        headers: newHeaders,
        cf: {
          polish: isMedia && cacheTtl > 0 ? 'lossy' : 'off',
          mirage: isMedia ? true : false,
        }
      };
      
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        fetchOptions.body = request.body;
      }
      
      return fetch(fetchUrl.toString(), fetchOptions);
    }
    
    response = await tryFetch('apiremake-production-4cd1.up.railway.app');
    
    const responseToCache = response.clone();
    const resHeaders = new Headers(response.headers);
    
    resHeaders.set('Access-Control-Allow-Origin', '*');
    resHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    resHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Accept, X-Stream, Range');
    resHeaders.set('Access-Control-Expose-Headers', '*');
    
    if (isMedia && cacheTtl > 0 && response.status === 200) {
      const contentType = response.headers.get('content-type') || '';
      const isPlaylist = contentType.includes('application/vnd.apple.mpegurl') || 
                        contentType.includes('application/dash+xml') ||
                        contentType.includes('application/x-mpegurl');
      
      if (isPlaylist) {
        resHeaders.set('Cache-Control', `public, max-age=${cacheTtl}, stale-while-revalidate=${cacheTtl/2}`);
        resHeaders.set('CDN-Cache-Control', `public, max-age=${cacheTtl}`);
        resHeaders.set('Cloudflare-CDN-Cache-Control', `public, max-age=${cacheTtl}`);
      } else {
        resHeaders.set('Cache-Control', `public, max-age=${cacheTtl}, stale-while-revalidate=${cacheTtl/2}`);
        resHeaders.set('CDN-Cache-Control', `public, max-age=${cacheTtl}`);
        resHeaders.set('Cloudflare-CDN-Cache-Control', `public, max-age=${cacheTtl}`);
      }
      
      resHeaders.set('CF-Cache-Status', 'MISS');
      resHeaders.set('X-Cache', 'MISS');
      
      if (url.pathname.match(/\.(mp4|webm|ts|m4s)$/i)) {
        resHeaders.set('Accept-Ranges', 'bytes');
      }
      
      if (request.method === 'GET') {
        ctx.waitUntil(
          (async () => {
            const cache = caches.default;
            const cachedResponse = new Response(responseToCache.body, {
              status: responseToCache.status,
              statusText: responseToCache.statusText,
              headers: resHeaders
            });
            await cache.put(cacheKey, cachedResponse);
          })()
        );
      }
    } else if (isStreamingRequest) {
      resHeaders.set('Cache-Control', 'no-cache, no-transform, must-revalidate');
      resHeaders.set('X-Accel-Buffering', 'no');
      resHeaders.set('CF-Cache-Status', 'DYNAMIC');
      resHeaders.set('Transfer-Encoding', 'chunked');
      resHeaders.set('Connection', 'keep-alive');
      resHeaders.set('Content-Type', 'text/event-stream');
      resHeaders.delete('content-length');
    } else {
      resHeaders.set('Cache-Control', 'no-cache');
      resHeaders.set('CF-Cache-Status', 'BYPASS');
    }
    
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: resHeaders
    });
  }
};