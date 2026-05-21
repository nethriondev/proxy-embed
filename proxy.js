export const config = { runtime: 'edge' };

const WORKER_URL = 'https://proxy-embed.nethriondev.workers.dev';

const FORBIDDEN_HEADERS = new Set([
  'host',
  'cookie',
  'set-cookie',
  'origin',
  'referer',
  'authorization',
  'proxy-authorization',
  'proxy-authenticate',
  'transfer-encoding',
  'connection',
  'keep-alive',
  'upgrade',
  'via',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'cf-connecting-ip',
  'cf-ray',
  'cf-worker',
  'x-real-ip',
]);

const PROXY_TIMEOUT_MS = 15_000;

const CORS_PREFLIGHT_RESPONSE = new Response(null, {
  status: 204,
  headers: {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH',
    'Access-Control-Allow-Headers': 'Content-Type, Accept, X-Stream, Range, Cache-Control',
    'Access-Control-Max-Age': '86400',
  }
});

function filterHeaders(headers) {
  const filtered = new Headers();
  for (const [key, value] of headers) {
    if (!FORBIDDEN_HEADERS.has(key.toLowerCase())) {
      filtered.set(key, value);
    }
  }
  return filtered;
}

export default async function handler(request) {
  if (request.method === 'OPTIONS') {
    return CORS_PREFLIGHT_RESPONSE;
  }

  const url = new URL(request.url);
  const workerUrl = new URL(url.pathname + url.search, WORKER_URL);

  const filteredHeaders = filterHeaders(request.headers);

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), PROXY_TIMEOUT_MS);

  try {
    const fetchOptions = {
      method: request.method,
      headers: filteredHeaders,
      signal: controller.signal,
    };

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      fetchOptions.body = request.body;
      fetchOptions.duplex = 'half';
    }

    const response = await fetch(workerUrl.toString(), fetchOptions);

    const responseHeaders = new Headers();
    for (const [key, value] of response.headers) {
      if (!FORBIDDEN_HEADERS.has(key.toLowerCase())) {
        responseHeaders.set(key, value);
      }
    }
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('Access-Control-Expose-Headers', '*');

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders
    });
  } catch (error) {
    if (error.name === 'AbortError') {
      return new Response('Gateway Timeout: Upstream did not respond in time', {
        status: 504,
        headers: {
          'Content-Type': 'text/plain',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }

    return new Response('Bad Gateway: Could not reach upstream', {
      status: 502,
      headers: {
        'Content-Type': 'text/plain',
        'Access-Control-Allow-Origin': '*'
      }
    });
  } finally {
    clearTimeout(timeoutId);
  }
}