addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const clientIP = request.headers.get('cf-connecting-ip') || 
                   request.headers.get('x-forwarded-for') || 
                   request.headers.get('x-real-ip') || 
                   request.headers.get('true-client-ip') || 
                   '0.0.0.0';
  
  const newHeaders = new Headers(request.headers);
  newHeaders.set('x-forwarded-for', clientIP);
  newHeaders.set('x-real-ip', clientIP);
  newHeaders.set('cf-connecting-ip', clientIP);
  newHeaders.set('x-client-ip', clientIP);
  
  async function tryFetch(hostname) {
    const url = new URL(request.url);
    url.hostname = hostname;
    url.protocol = 'https:';
    url.port = '443';
    
    const headers = new Headers(newHeaders);
    headers.set('host', hostname);
    
    return fetch(url.toString(), {
      method: request.method,
      headers: headers,
      body: request.body,
      cf: { 
        cacheTtl: 0,
        cacheEverything: false
      }
    });
  }

  const response = await tryFetch('apiremake-production.up.railway.app');
  const resHeaders = new Headers(response.headers);
  resHeaders.set('Access-Control-Allow-Origin', '*');
  resHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  resHeaders.set('Access-Control-Allow-Headers', '*');
  
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: resHeaders
  });
}
