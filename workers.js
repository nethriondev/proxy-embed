const ORIGIN_URLS = [
  'https://apiremake-production-7612.up.railway.app',
  'https://oreo-h3pv.onrender.com'
];
// nega
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

const startTime = Date.now();

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

const cleanMaps = () => {
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
};

function getDashboardStats() {
  const now = Date.now();
  const windowMs = RATE_LIMIT_WINDOW_MS;
  const windowStart = now - windowMs;

  let totalRequests = 0;
  const activeIps = [];
  for (const [ip, timestamps] of ipRequests) {
    const recent = timestamps.filter(t => t >= windowStart);
    if (recent.length > 0) {
      totalRequests += recent.length;
      activeIps.push({ ip, requests: recent.length });
    }
  }

  const bannedList = [];
  for (const [ip, until] of bannedIps) {
    bannedList.push({ ip, until: new Date(until).toISOString(), remainingMs: Math.max(0, until - now) });
  }

  const attacks = [];
  for (const [path, attack] of pathsUnderAttack) {
    attacks.push({
      path,
      active: attack.active,
      count: attack.count,
      ip: attack.ip,
      triggeredAt: new Date(attack.triggeredAt).toISOString(),
      windowMs: attack.windowMs
    });
  }

  return {
    startTime: new Date(startTime).toISOString(),
    uptimeMs: now - startTime,
    totalTrackedIps: ipRequests.size,
    activeRequestsThisWindow: totalRequests,
    activeIps: activeIps.sort((a, b) => b.requests - a.requests).slice(0, 20),
    bannedIps: bannedList,
    pathsUnderAttack: attacks,
    rateLimit: {
      windowMs: RATE_LIMIT_WINDOW_MS,
      maxRequests: MAX_REQUESTS_PER_WINDOW,
      banThreshold: BAN_THRESHOLD,
      banDurationMs: BAN_DURATION_MS,
    },
    cacheConfig: CACHE_CONFIG,
    ipPathAttackThreshold: IP_PATH_ATTACK_THRESHOLD,
    trustedIpsCount: trustedIps.size,
    blockedIpsCount: BLOCKED_IPS.length,
  };
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
  if (clientIpHeader) {
    return clientIpHeader;
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

function getCacheTtl(url, responseContentType, hasRangeHeader, responseStatus, ext, contentLength) {
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

async function fetchFromFastestOrigin(url, fetchOptions) {
  const promises = ORIGIN_URLS.map(async (originUrl) => {
    const fetchUrl = new URL(url.toString());
    fetchUrl.hostname = new URL(originUrl).hostname;
    fetchUrl.protocol = 'https:';
    fetchUrl.port = '443';

    const response = await fetch(fetchUrl.toString(), fetchOptions);
    if (response.status < 400) {
      return response;
    }
    throw new Error(`${originUrl} returned ${response.status}`);
  });

  try {
    return await Promise.any(promises);
  } catch {
    throw new Error('All origins failed');
  }
}

async function fetchWebSocketFromFastestOrigin(request) {
  const promises = ORIGIN_URLS.map(async (originUrl) => {
    const url = new URL(request.url);
    url.hostname = new URL(originUrl).hostname;
    url.protocol = 'https:';
    url.port = '443';

    const response = await fetch(url.toString(), request);
    if (response.status === 101 || response.status < 400) {
      return response;
    }
    throw new Error(`${originUrl} returned ${response.status}`);
  });

  try {
    return await Promise.any(promises);
  } catch {
    throw new Error('All WebSocket origins failed');
  }
}

async function proxyRequestToOrigin(request, clientIP, env, ctx) {
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

  const cache = caches.default;
  const cacheKey = new Request(url.toString(), request);
  let cachedResponse = await cache.match(cacheKey);
  let fromCache = false;
  
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
      cf: { cacheEverything: true, polish: 'lossy', mirage: true }
    };

    if (rangeHeader) {
      fetchOptions.headers.set('Range', rangeHeader);
    }

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      fetchOptions.body = request.body;
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
      ctx.waitUntil(fetch(originUrl, { method: 'HEAD' }).catch(() => {}));
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
  const cacheTtl = getCacheTtl(url, contentType, !!rangeHeader, cachedResponse.status, ext, contentLength);
  const shouldCache = cacheTtl > 0 && (cachedResponse.status === 200 || cachedResponse.status === 206);

  if (shouldCache) {
    resHeaders.set('Cache-Control', `public, max-age=${cacheTtl}, stale-while-revalidate=${Math.floor(cacheTtl/2)}`);
    resHeaders.set('CDN-Cache-Control', `public, max-age=${cacheTtl}`);
    resHeaders.set('X-Cache', fromCache ? 'HIT' : 'MISS');
    resHeaders.set('CF-Cache-Status', fromCache ? 'HIT' : 'MISS');
    resHeaders.set('Vary', 'Accept-Encoding, Range');
  } else {
    resHeaders.set('Cache-Control', 'no-cache, no-store, must-revalidate');
    resHeaders.set('CDN-Cache-Control', 'no-cache, no-store, must-revalidate');
  }

  const isSegment = pathname.match(/\.(ts|m4s)$/i);
  const isVideo = pathname.match(/\.(mp4|webm|avi|mov|mkv)$/i);
  const isAudio = pathname.match(/\.(mp3|wav|ogg|m4a|flac|aac)$/i);
  const isManifest = pathname.match(/\.(m3u8|mpd)$/i);
  const isMedia = isSegment || isVideo || isAudio || isManifest;

  if (isMedia && shouldCache) {
    if (!fromCache) {
      const cacheClone = cachedResponse.clone();
      ctx.waitUntil(cache.put(cacheKey, cacheClone));
    }
    return new Response(cachedResponse.body, {
      status: cachedResponse.status,
      statusText: cachedResponse.statusText,
      headers: resHeaders
    });
  }

  const responseBody = await cachedResponse.arrayBuffer();
  
  if (shouldCache && !noCache && !fromCache) {
    const newResponse = new Response(responseBody, {
      status: cachedResponse.status,
      statusText: cachedResponse.statusText,
      headers: resHeaders
    });
    ctx.waitUntil(cache.put(cacheKey, newResponse.clone()));
  }

  return new Response(responseBody, {
    status: cachedResponse.status,
    statusText: cachedResponse.statusText,
    headers: resHeaders
  });
}

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Proxy Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f1117;color:#e1e4e8;padding:20px}
h1{font-size:1.5rem;margin-bottom:20px;color:#58a6ff}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;margin-bottom:24px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px}
.card h3{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;color:#8b949e;margin-bottom:8px}
.card .value{font-size:1.75rem;font-weight:600;color:#f0f6fc}
.card .sub{font-size:.8rem;color:#8b949e;margin-top:4px}
table{width:100%;border-collapse:collapse;font-size:.875rem}
th{text-align:left;padding:8px 12px;border-bottom:2px solid #30363d;color:#8b949e;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}
td{padding:8px 12px;border-bottom:1px solid #21262d}
.section{margin-bottom:24px}
.section h2{font-size:1.1rem;color:#58a6ff;margin-bottom:12px}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.75rem;font-weight:500}
.badge-red{background:#da3633;color:#fff}
.badge-yellow{background:#d29922;color:#fff}
.badge-green{background:#238636;color:#fff}
.badge-gray{background:#30363d;color:#8b949e}
.empty{color:#8b949e;font-style:italic;padding:16px;text-align:center}
#refresh-info{text-align:center;color:#8b949e;font-size:.8rem;margin-top:20px}
@media(max-width:600px){.stats-grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<h1>Proxy Dashboard</h1>
<div class="stats-grid" id="summary"></div>
<div class="section"><h2>Active IPs (top 20)</h2><div id="active-ips"></div></div>
<div class="section"><h2>Banned IPs</h2><div id="banned-ips"></div></div>
<div class="section"><h2>Paths Under Attack</h2><div id="attacks"></div></div>
<div id="refresh-info">Auto-refreshes every 5s</div>
<script>
async function load(){try{const r=await fetch('?json'),d=await r.json();render(d)}catch(e){document.body.innerHTML='<p style=color:#da3633>Failed to load dashboard</p>'}}
function render(d){
let s='',cards=[
{label:'Uptime',val:fmtUptime(d.uptimeMs),sub:'since '+new Date(d.startTime).toLocaleTimeString()},
{label:'Active IPs',val:d.totalTrackedIps,sub:d.activeRequestsThisWindow+' requests in window'},
{label:'Banned IPs',val:d.bannedIps.length,sub:'out of '+d.blockedIpsCount+' blocked'},
{label:'Paths Under Attack',val:d.pathsUnderAttack.length,sub:'threshold: '+d.ipPathAttackThreshold},
{label:'Rate Limit',val:d.rateLimit.maxRequests+'/min',sub:'ban after '+d.rateLimit.banThreshold+' violations'},
];
cards.forEach(c=>{s+='<div class=card><h3>'+c.label+'</h3><div class=value>'+c.val+'</div>'+(c.sub?'<div class=sub>'+c.sub+'</div>':'')+'</div>'});
document.getElementById('summary').innerHTML=s;
let t='';if(d.activeIps.length){t+='<table><tr><th>IP</th><th>Requests</th></tr>';d.activeIps.forEach(a=>{t+='<tr><td>'+a.ip+'</td><td>'+a.requests+'</td></tr>'});t+='</table>'}else{t='<div class=empty>No active IPs</div>'}
document.getElementById('active-ips').innerHTML=t;
t='';if(d.bannedIps.length){t+='<table><tr><th>IP</th><th>Remaining</th><th>Expires</th></tr>';d.bannedIps.forEach(b=>{t+='<tr><td>'+b.ip+'</td><td><span class=badge badge-red>'+fmtDur(b.remainingMs)+'</span></td><td>'+new Date(b.until).toLocaleTimeString()+'</td></tr>'});t+='</table>'}else{t='<div class=empty>None</div>'}
document.getElementById('banned-ips').innerHTML=t;
t='';if(d.pathsUnderAttack.length){t+='<table><tr><th>Path</th><th>Count</th><th>IP</th><th>Triggered</th></tr>';d.pathsUnderAttack.forEach(a=>{t+='<tr><td><code>'+a.path+'</code></td><td><span class=badge badge-yellow>'+a.count+'</span></td><td>'+a.ip+'</td><td>'+new Date(a.triggeredAt).toLocaleTimeString()+'</td></tr>'});t+='</table>'}else{t='<div class=empty>None</div>'}
document.getElementById('attacks').innerHTML=t;
}
function fmtUptime(ms){const s=Math.floor(ms/1000);if(s<60)return s+'s';const m=Math.floor(s/60);if(m<60)return m+'m '+s%60+'s';const h=Math.floor(m/60);return h+'h '+m%60+'m'}
function fmtDur(ms){const s=Math.ceil(ms/1000);if(s<60)return s+'s';const m=Math.floor(s/60);return m+'m'}
load();setInterval(load,5000);
</script>
</body>
</html>`;

export default {
  async fetch(request, env, ctx) {
    try {
      const clientIP = getClientIp(request);
      
      const url = new URL(request.url);
      
      if (url.pathname === '/dashboard') {
        const isJson = url.searchParams.has('json');
        if (isJson) {
          return new Response(JSON.stringify(getDashboardStats()), {
            status: 200,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
          });
        }
        return new Response(DASHBOARD_HTML, {
          status: 200,
          headers: { 'Content-Type': 'text/html;charset=utf-8' }
        });
      }
      
      recordPathRequest(clientIP, url.pathname);

      if (trustedIps.has(clientIP) || internalProxyIps.has(clientIP)) {
        return await proxyRequestToOrigin(request, clientIP, env, ctx);
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
|     /-----------------------------------\\       |
|     |  You have been permanently banned |        |
|    \\-----------------------------------/        |
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

      const result = await proxyRequestToOrigin(request, clientIP, env, ctx);
      ctx.waitUntil(Promise.resolve(cleanMaps()));
      return result;
    } catch (error) {
      return new Response('Internal Server Error', { 
        status: 500,
        headers: { 'Content-Type': 'text/plain' }
      });
    }
  }
};