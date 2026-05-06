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

function getCacheTtl(url, responseContentType) {
  const pathname = url.pathname.toLowerCase();
  
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
    
    const cacheKey = new Request(url.toString(), request);
    let response = null;
    
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
          polish: 'lossy',
          mirage: true,
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
    const contentType = response.headers.get('content-type') || '';
    const cacheTtl = getCacheTtl(url, contentType);
    
    resHeaders.set('Access-Control-Allow-Origin', '*');
    resHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    resHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Accept, X-Stream, Range');
    resHeaders.set('Access-Control-Expose-Headers', '*');
    
    const shouldCache = cacheTtl > 0 && response.status === 200;
    
    if (shouldCache) {
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