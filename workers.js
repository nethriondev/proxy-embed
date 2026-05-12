const ORIGIN_URLS = [
  'https://apiremake-production-4552.up.railway.app',
];

const BLOCKED_IPS = [
  '1.2.3.4'
];

const getClientIp = (request) => {
  const cfConnectingIp = request.headers.get('cf-connecting-ip');
  if (cfConnectingIp) {
    return cfConnectingIp;
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
    const lastIp = ips[ips.length - 1]?.trim();
    if (lastIp && lastIp !== 'unknown') return lastIp;
  }

  const xRealIp = request.headers.get('x-real-ip');
  if (xRealIp) {
    return xRealIp;
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
      
      lastError = new Error(`Origin ${originUrl} returned status ${response.status}`);
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError || new Error('All origins failed');
}

export default {
  async fetch(request, env, ctx) {
    try {
      const clientIP = getClientIp(request);
      
      if (BLOCKED_IPS.includes(clientIP)) {
        return new Response('Forbidden', { 
          status: 403,
          headers: {
            'Content-Type': 'text/plain'
          }
        });
      }
      
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
        return new Response('Origin server error', { 
          status: 502,
          headers: {
            'Content-Type': 'text/plain'
          }
        });
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