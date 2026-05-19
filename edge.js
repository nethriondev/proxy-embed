export const config = {
  runtime: 'edge'
};

const ORIGIN_URL = 'https://proxy-embed.nethriondev.workers.dev';

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
  PARTIAL_TTL: 3600,
  FULL_TTL: 604800,
  MANIFEST_TTL: 43200,
  ATTACK_PUNISHMENT_TTL: 300,
  CHUNK_SIZE: 1024 * 1024
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
  const clientIpHeader = request.headers.get('x-client-ip');
  if (clientIpHeader) return clientIpHeader;

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

const parseRangeHeader = (rangeHeader, fileSize) => {
  const matches = rangeHeader.match(/bytes=(\d+)-(\d*)/);
  if (!matches) return null;
  
  let start = parseInt(matches[1], 10);
  let end = matches[2] ? parseInt(matches[2], 10) : fileSize - 1;
  
  start = Math.min(Math.max(0, start), fileSize - 1);
  end = Math.min(end, fileSize - 1);
  
  return { start, end };
};

async function getVideoChunk(url, start, end, clientIP) {
  const chunkKey = new Request(`${url.toString()}?chunk=${start}-${end}`, {
    headers: { 'Range': `bytes=${start}-${end}` }
  });
  
  const cache = caches.default;
  let cached = await cache.match(chunkKey);
  
  if (!cached) {
    const fetchUrl = new URL(url.pathname + url.search, ORIGIN_URL);
    const headers = new Headers();
    headers.set('Range', `bytes=${start}-${end}`);
    headers.set('x-forwarded-for', clientIP);
    headers.set('x-real-ip', clientIP);
    headers.set('cf-connecting-ip', clientIP);
    
    try {
      cached = await fetch(fetchUrl.toString(), {
        method: 'GET',
        headers: headers,
        cf: { cacheEverything: true }
      });
      
      if (cached.status === 206 || cached.status === 200) {
        const responseToCache = cached.clone();
        await cache.put(chunkKey, responseToCache);
      }
    } catch (error) {
      return new Response('Chunk fetch error', { status: 502 });
    }
  }
  
  return cached;
}

async function handleLargeMediaWithChunks(request, url, clientIP) {
  const cache = caches.default;
  const rangeHeader = request.headers.get('range');
  const CHUNK_SIZE = CACHE_CONFIG.CHUNK_SIZE;
  
  const headKey = new Request(`${url.toString()}?head=true`, { method: 'HEAD' });
  let headResponse = await cache.match(headKey);
  
  if (!headResponse) {
    const fetchUrl = new URL(url.pathname, ORIGIN_URL);
    const headFetch = await fetch(fetchUrl.toString(), {
      method: 'HEAD',
      headers: { 'x-forwarded-for': clientIP }
    });
    headResponse = new Response(null, {
      headers: headFetch.headers
    });
    await cache.put(headKey, headResponse.clone());
  }
  
  const contentLength = parseInt(headResponse.headers.get('content-length') || '0');
  if (!contentLength) {
    return null;
  }
  
  if (!rangeHeader) {
    const chunkStart = 0;
    const chunkEnd = Math.min(CHUNK_SIZE - 1, contentLength - 1);
    return await getVideoChunk(url, chunkStart, chunkEnd, clientIP);
  }
  
  const parsedRange = parseRangeHeader(rangeHeader, contentLength);
  if (!parsedRange) {
    return new Response('Invalid Range', { status: 416 });
  }
  
  let { start, end } = parsedRange;
  const requestedLength = end - start + 1;
  
  if (requestedLength < CHUNK_SIZE) {
    const chunkStart = Math.floor(start / CHUNK_SIZE) * CHUNK_SIZE;
    const chunkEnd = Math.min(chunkStart + CHUNK_SIZE - 1, contentLength - 1);
    const chunk = await getVideoChunk(url, chunkStart, chunkEnd, clientIP);
    
    if (!chunk || chunk.status !== 206) {
      return chunk;
    }
    
    const chunkData = await chunk.arrayBuffer();
    const offsetInChunk = start - chunkStart;
    const sliceEnd = Math.min(offsetInChunk + requestedLength, chunkData.byteLength);
    const slicedData = chunkData.slice(offsetInChunk, sliceEnd);
    
    const headers = new Headers();
    headers.set('Content-Type', chunk.headers.get('content-type') || 'video/mp4');
    headers.set('Content-Range', `bytes ${start}-${end}/${contentLength}`);
    headers.set('Content-Length', slicedData.byteLength.toString());
    headers.set('Accept-Ranges', 'bytes');
    headers.set('Access-Control-Allow-Origin', '*');
    headers.set('Cache-Control', `public, max-age=${CACHE_CONFIG.PARTIAL_TTL}`);
    
    return new Response(slicedData, {
      status: 206,
      statusText: 'Partial Content',
      headers: headers
    });
  }
  
  const chunks = [];
  let currentStart = start;
  
  while (currentStart <= end) {
    const chunkEnd = Math.min(currentStart + CHUNK_SIZE - 1, end);
    const chunk = await getVideoChunk(url, currentStart, chunkEnd, clientIP);
    if (chunk && chunk.body) {
      chunks.push(chunk.body);
    }
    currentStart = chunkEnd + 1;
  }
  
  const stream = new ReadableStream({
    async start(controller) {
      for (const chunkBody of chunks) {
        const reader = chunkBody.getReader();
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          controller.enqueue(value);
        }
      }
      controller.close();
    }
  });
  
  const headers = new Headers();
  headers.set('Content-Type', 'video/mp4');
  headers.set('Content-Range', `bytes ${start}-${end}/${contentLength}`);
  headers.set('Content-Length', (end - start + 1).toString());
  headers.set('Accept-Ranges', 'bytes');
  headers.set('Access-Control-Allow-Origin', '*');
  
  return new Response(stream, {
    status: 206,
    statusText: 'Partial Content',
    headers: headers
  });
}

function getCacheTtl(url, responseContentType, hasRangeHeader, responseStatus, contentLength) {
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
  
  if (pathname.match(/\.(ts|m4s)$/i)) {
    return CACHE_CONFIG.SEGMENT_TTL;
  }
  
  if (pathname.match(/\.(mp4|webm|avi|mov|mkv)$/i)) {
    if (contentLength > 10 * 1024 * 1024) {
      return 0;
    }
    if (hasRangeHeader) {
      return CACHE_CONFIG.PARTIAL_TTL;
    }
    return CACHE_CONFIG.FULL_TTL;
  }
  
  if (pathname.match(/\.(mp3|wav|ogg|m4a|flac|aac)$/i)) {
    if (contentLength > 10 * 1024 * 1024) {
      return 0;
    }
    if (hasRangeHeader) {
      return CACHE_CONFIG.PARTIAL_TTL;
    }
    return CACHE_CONFIG.FULL_TTL;
  }
  
  if (pathname.endsWith('.m3u8') || 
      pathname.endsWith('.mpd') ||
      responseContentType.includes('application/vnd.apple.mpegurl') ||
      responseContentType.includes('application/x-mpegurl') ||
      responseContentType.includes('application/dash+xml')) {
    return CACHE_CONFIG.MANIFEST_TTL;
  }
  
  if (pathname.match(/\.(jpg|jpeg|png|gif|webp|bmp|svg|ico)$/i)) {
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

async function proxyRequestToOrigin(request, clientIP) {
  if (request.headers.get('upgrade')?.toLowerCase() === 'websocket') {
    const url = new URL(request.url);
    url.hostname = new URL(ORIGIN_URL).hostname;
    url.protocol = 'https:';
    url.port = '443';
    return fetch(url.toString(), request);
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
  
  const isLargeMediaFile = pathname.match(/\.(mp4|webm|avi|mov|mkv|mp3|wav|ogg|m4a|flac|aac)$/i);
  
  if (isLargeMediaFile) {
    const chunkedResponse = await handleLargeMediaWithChunks(request, url, clientIP);
    if (chunkedResponse) {
      return chunkedResponse;
    }
  }
  
  const rangeHeader = request.headers.get('range');
  
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
  };

  if (rangeHeader) {
    fetchOptions.headers.set('Range', rangeHeader);
  }

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    fetchOptions.body = request.body;
  }

  let originResponse;
  try {
    originResponse = await fetch(fetchUrl.toString(), fetchOptions);
  } catch (error) {
    return new Response('Origin server error', {
      status: 502,
      headers: { 'Content-Type': 'text/plain' }
    });
  }

  const contentType = originResponse.headers.get('content-type') || '';
  const resHeaders = new Headers(originResponse.headers);
  const contentLength = parseInt(originResponse.headers.get('content-length') || '0');

  if (originResponse.status === 206) {
    const contentRange = originResponse.headers.get('content-range');
    if (contentRange) {
      resHeaders.set('content-range', contentRange);
    }
    resHeaders.set('accept-ranges', 'bytes');
  }

  resHeaders.delete('x-railway-edge');
  resHeaders.delete('x-railway-request-id');
  resHeaders.delete('x-cache');
  resHeaders.delete('cf-cache-status');

  resHeaders.set('Access-Control-Allow-Origin', '*');
  resHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  resHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Accept, X-Stream, Range');
  resHeaders.set('Access-Control-Expose-Headers', '*');

  const cacheTtl = getCacheTtl(url, contentType, !!rangeHeader, originResponse.status, contentLength);
  const shouldCache = cacheTtl > 0 && (originResponse.status === 200 || originResponse.status === 206) && !isLargeMediaFile;
  const isMedia = pathname.match(/\.(ts|m4s|mp4|webm|avi|mov|mkv|mp3|wav|ogg|m4a|flac|aac|m3u8|mpd)$/i);

  if (shouldCache) {
    if (isPathUnderAttack(pathname) && contentType.includes('application/json')) {
      resHeaders.set('Cache-Control', `public, max-age=${CACHE_CONFIG.ATTACK_PUNISHMENT_TTL}, stale-while-revalidate=0`);
    } else {
      resHeaders.set('Cache-Control', `public, max-age=${cacheTtl}, stale-while-revalidate=${Math.floor(cacheTtl/2)}`);
    }
    resHeaders.set('CDN-Cache-Control', `public, max-age=${cacheTtl}`);
    resHeaders.set('Vary', 'Accept-Encoding, Range');
  } else {
    resHeaders.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  }

  if (isMedia && !isLargeMediaFile) {
    return new Response(originResponse.body, {
      status: originResponse.status,
      statusText: originResponse.statusText,
      headers: resHeaders
    });
  }

  const responseBody = await originResponse.arrayBuffer();
  
  return new Response(responseBody, {
    status: originResponse.status,
    statusText: originResponse.statusText,
    headers: resHeaders
  });
}

setInterval(() => {
  cleanMaps();
}, 15000);

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
        return new Response('Too Many Requests', {
          status: 429,
          headers: { 'Content-Type': 'text/plain', 'Retry-After': '300' }
        });
      }
      bannedIps.delete(clientIP);
    }

    if (BLOCKED_IPS.includes(clientIP)) {
    const asciiTroll = `
+--------------------------------------------------+
|               ACCESS DENIED                      |
+--------------------------------------------------+
|      IP ni tangang skid: ${clientIP}             |
|     (\\_/)                                       |
|     (o.o)    Nice try, script kiddie             |
|     (> <)    Your IP has been logged             |
|                                                  |
|     ╔══════════════════════════════════╗         |
|     ║  Your hacking skills:            ║         |
|     ║  [#-------------------] 1 %      ║         |
|     ║  Keep trying, maybe next decade  ║         |
|     ╚══════════════════════════════════╝         |
|        Hina ng ddos mo tanga!                    |
|     /----------------------------------\\        |
|     |  You have been permanently banned |        |
|     \\----------------------------------/        |
|                                                  |
+--------------------------------------------------+
  `;
  
  return new Response(asciiTroll, { 
    status: 403,
    headers: { 
      'Content-Type': 'text/plain',
      'Dumb-Skid-Ip': clientIP
    }
  });
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
      return new Response('Too Many Requests', {
        status: 429,
        headers: { 'Content-Type': 'text/plain', 'Retry-After': '300' }
      });
    }
    timestamps.push(now);

    const result = await proxyRequestToOrigin(request, clientIP);
    return result;
  } catch (error) {
    return new Response('Internal Server Error', { 
      status: 500,
      headers: { 'Content-Type': 'text/plain' }
    });
  }
}