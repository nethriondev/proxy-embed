export const config = {
  runtime: 'edge'
};

const ORIGIN_URLS = [
  'https://proxy-embed.nethriondev.workers.dev',
  'https://apiremake-production-7612.up.railway.app'
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

const INTERNAL_PROXY_IPS = ["162.220.234.134"];

const RATE_LIMIT_WINDOW_MS = 60000;
const MAX_REQUESTS_PER_WINDOW = 200;
const BAN_THRESHOLD = 3;
const BAN_DURATION_MS = 900000;

const CACHE_CONFIG = {
  SEGMENT_TTL: 86400,
  PARTIAL_TTL: 86400,
  FULL_TTL: 604800,
  MANIFEST_TTL: 43200,
  ATTACK_PUNISHMENT_TTL: 300
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
    let lastError;
    for (const originUrl of ORIGIN_URLS) {
      const url = new URL(request.url);
      url.hostname = new URL(originUrl).hostname;
      url.protocol = 'https:';
      url.port = '443';
      try {
        return await fetch(url.toString(), request);
      } catch (error) {
        lastError = error;
      }
    }
    return new Response('WebSocket connection failed', {
      status: 502,
      headers: { 'Content-Type': 'text/plain' }
    });
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
  
  const newHeaders = new Headers(request.headers);
  newHeaders.set('x-forwarded-for', clientIP);
  newHeaders.set('x-real-ip', clientIP);
  newHeaders.set('cf-connecting-ip', clientIP);

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
  let lastError;
  for (const originUrl of ORIGIN_URLS) {
    const fetchUrl = new URL(url.toString());
    fetchUrl.hostname = new URL(originUrl).hostname;
    fetchUrl.protocol = 'https:';
    fetchUrl.port = '443';

    try {
      originResponse = await fetch(fetchUrl.toString(), fetchOptions);
      lastError = null;
      break;
    } catch (error) {
      lastError = error;
    }
  }

  if (lastError) {
    return new Response('Origin server error', {
      status: 502,
      headers: { 'Content-Type': 'text/plain' }
    });
  }

  for (const originUrl of ORIGIN_URLS) {
    if (!SERVERLESS_DOMAINS.some(d => originUrl.includes(d))) continue;
    fetch(originUrl, { method: 'HEAD' }).catch(() => {});
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
  const shouldCache = cacheTtl > 0 && (originResponse.status === 200 || originResponse.status === 206);
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

  if (isMedia) {
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
  for (const originUrl of ORIGIN_URLS) {
    if (!SERVERLESS_DOMAINS.some(d => originUrl.includes(d))) continue;
    fetch(originUrl, { method: 'HEAD' }).catch(() => {});
  }
}, 30000);

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