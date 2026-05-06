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
    const clientIP = getClientIp(request);
    
    const newHeaders = new Headers(request.headers);
    newHeaders.set('x-forwarded-for', clientIP);
    newHeaders.set('x-real-ip', clientIP);
    newHeaders.set('cf-connecting-ip', clientIP);
    
    const acceptHeader = request.headers.get('accept') || '';
    const isStreamingRequest = acceptHeader.includes('text/event-stream') || 
                              acceptHeader.includes('application/stream+json') ||
                              request.headers.get('x-stream') === 'true';

    async function tryFetch(hostname) {
      const url = new URL(request.url);
      url.hostname = hostname;
      url.protocol = 'https:';
      url.port = '443';
      
      return fetch(url.toString(), {
        method: request.method,
        headers: newHeaders,
        body: request.body,
        cf: {
          cacheTtl: 0,
          cacheEverything: false,
        }
      });
    }

    const response = await tryFetch('apiremake-production-4cd1.up.railway.app');
    
    const resHeaders = new Headers(response.headers);
    
    resHeaders.set('Access-Control-Allow-Origin', '*');
    resHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    resHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Accept, X-Stream');
    resHeaders.set('Access-Control-Expose-Headers', '*');
    
    if (isStreamingRequest) {
      resHeaders.set('Cache-Control', 'no-cache, no-transform, must-revalidate');
      resHeaders.set('X-Accel-Buffering', 'no');
      resHeaders.set('CF-Cache-Status', 'DYNAMIC');
      resHeaders.set('Transfer-Encoding', 'chunked');
      resHeaders.set('Connection', 'keep-alive');
      resHeaders.set('Content-Type', 'text/event-stream');
      resHeaders.delete('content-length');
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: resHeaders
    });
  }
};