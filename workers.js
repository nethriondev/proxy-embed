export default {
  async fetch(request, env, ctx) {
    return handleRequest(request);
  }
};

async function handleRequest(request) {
  const url = new URL(request.url);
  const originalHost = url.hostname;
  const clientIP = request.headers.get('cf-connecting-ip') || 
                   request.headers.get('x-forwarded-for') || 
                   request.headers.get('x-real-ip') || 
                   '';
  
  const acceptHeader = request.headers.get('accept') || '';
  const isStreamingRequest = acceptHeader.includes('text/event-stream') || 
                            acceptHeader.includes('application/stream+json') ||
                            request.headers.get('x-stream') === 'true';

  const proxyUrl = new URL(request.url);
  proxyUrl.hostname = 'apiremake-production.up.railway.app';
  proxyUrl.protocol = 'https:';
  proxyUrl.port = '443';
  
  const newHeaders = new Headers(request.headers);
  
  newHeaders.set('host', originalHost);
  newHeaders.set('x-forwarded-host', originalHost);
  newHeaders.set('x-forwarded-proto', 'https');
  newHeaders.set('x-original-host', originalHost);
  
  if (clientIP) {
    newHeaders.set('x-forwarded-for', clientIP);
    newHeaders.set('x-real-ip', clientIP);
    newHeaders.set('cf-connecting-ip', clientIP);
  }
  
  const modifiedRequest = new Request(proxyUrl.toString(), {
    method: request.method,
    headers: newHeaders,
    body: request.body,
    cf: {
      cacheTtl: 0,
      cacheEverything: false,
    }
  });

  const response = await fetch(modifiedRequest);
  
  const resHeaders = new Headers(response.headers);
  
  resHeaders.set('Access-Control-Allow-Origin', '*');
  resHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  resHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Accept, X-Stream');
  
  if (isStreamingRequest) {
    resHeaders.set('Cache-Control', 'no-cache, no-transform, must-revalidate');
    resHeaders.set('X-Accel-Buffering', 'no');
    resHeaders.set('Transfer-Encoding', 'chunked');
    resHeaders.set('Connection', 'keep-alive');
    
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: resHeaders
    });
  } else {
    return new Response(await response.arrayBuffer(), {
      status: response.status,
      statusText: response.statusText,
      headers: resHeaders
    });
  }
}