export const config = {
  runtime: 'edge'
};

const WORKER_URL = 'https://proxy-embed.nethriondev.workers.dev';

const CACHE_CONFIG = {
  SEGMENT_TTL: 86400,
  PARTIAL_TTL: 86400,
  FULL_TTL: 604800,
  MANIFEST_TTL: 43200,
  ATTACK_PUNISHMENT_TTL: 300
};

function getCacheTtl(url, responseContentType, hasRangeHeader, responseStatus, contentLength, ext) {
  const pathname = url.pathname.toLowerCase();
  
  if (responseStatus < 200 || responseStatus >= 400) {
    return 0;
  }
  
  if (responseContentType.includes('application/json')) {
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

export default async function handler(request) {
  const url = new URL(request.url);
  const workerUrl = new URL(url.pathname + url.search, WORKER_URL);
  
  const rangeHeader = request.headers.get('range');
  const cache = caches.default;
  const cacheKeyOptions = { method: request.method };
  if (rangeHeader) {
    cacheKeyOptions.headers = { Range: rangeHeader };
  }
  const cacheKey = new Request(workerUrl.toString(), cacheKeyOptions);
  
  let response = await cache.match(cacheKey);
  let fromCache = false;
  
  if (!response) {
    const fetchOptions = {
      method: request.method,
      headers: request.headers,
    };
    
    if (rangeHeader) {
      fetchOptions.headers.set('Range', rangeHeader);
    }
    
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      fetchOptions.body = request.body;
    }
    
    response = await fetch(workerUrl.toString(), fetchOptions);
    
    const contentType = response.headers.get('content-type') || '';
    const contentLength = parseInt(response.headers.get('content-length') || '0');
    const ext = url.searchParams.get('ext') || undefined;
    const cacheTtl = getCacheTtl(url, contentType, !!rangeHeader, response.status, contentLength, ext);
    const shouldCache = cacheTtl > 0 && (response.status === 200 || response.status === 206);
    
    if (shouldCache) {
      const responseToCache = response.clone();
      const cachedResponse = new Response(responseToCache.body, {
        status: responseToCache.status,
        statusText: responseToCache.statusText,
        headers: {
          ...Object.fromEntries(responseToCache.headers),
          'Cache-Control': `public, max-age=${cacheTtl}, stale-while-revalidate=${Math.floor(cacheTtl/2)}`,
          'CDN-Cache-Control': `public, max-age=${cacheTtl}`,
          'Vercel-CDN-Cache-Control': `public, max-age=${cacheTtl}`,
          'X-Cache': 'MISS'
        }
      });
      await cache.put(cacheKey, cachedResponse);
    }
    fromCache = false;
  } else {
    fromCache = true;
  }
  
  const headers = new Headers(response.headers);
  headers.set('X-Cache', fromCache ? 'HIT' : 'MISS');
  headers.set('X-Upstream', 'vercel-edge');
  headers.delete('Vary');
  
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: headers
  });
}