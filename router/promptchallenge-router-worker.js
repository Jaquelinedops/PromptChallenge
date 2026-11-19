// Cloudflare Worker. Route only cyberactivity.com.br/promptchallenge and /promptchallenge/*
// The existing cyberactivity.com.br site continues to handle all other paths.
//
// Required Worker secret (same value configured in the Pages project):
//   PROXY_SHARED_SECRET  - random string, at least 32 characters (e.g. `openssl rand -hex 32`)
// The Worker signs the real client IP with HMAC-SHA256. The Pages backend rejects any /api request
// without a valid signature, so direct calls to promptchallenge.pages.dev (and preview URLs) are refused
// and per-IP rate limits use the real client IP instead of the Worker's egress IP.
const PUBLIC_ORIGIN = 'https://cyberactivity.com.br';
const TARGET_ORIGIN = 'https://promptchallenge.pages.dev';
const BASE = '/promptchallenge';
const encoder = new TextEncoder();
const toHex = buf => [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, '0')).join('');

async function sign(secret, message) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return toHex(await crypto.subtle.sign('HMAC', key, encoder.encode(message)));
}

export default {
  async fetch(request, env) {
    const incoming = new URL(request.url);
    if (incoming.origin !== PUBLIC_ORIGIN ||
        (incoming.pathname !== BASE && !incoming.pathname.startsWith(BASE + '/'))) {
      return new Response('Not found', { status: 404 });
    }

    // Canonical slash is necessary so relative JS, CSS and API paths work.
    if (incoming.pathname === BASE) {
      const canonical = new URL(incoming.href);
      canonical.pathname = BASE + '/';
      return Response.redirect(canonical.href, 308);
    }

    // Reject cross-site browser POSTs before converting Origin for the Pages backend.
    if (!['GET', 'HEAD', 'POST'].includes(request.method)) {
      return new Response('Method not allowed', {status: 405});
    }
    const originalOrigin = request.headers.get('Origin');
    if (request.method === 'POST' && originalOrigin !== PUBLIC_ORIGIN) {
      return new Response('Invalid origin', {status: 403});
    }

    const secret = env.PROXY_SHARED_SECRET;
    if (!secret || secret.length < 32) {
      console.error('PROXY_SHARED_SECRET missing or too short');
      return new Response('Service unavailable', { status: 503 });
    }

    const destination = new URL(TARGET_ORIGIN);
    destination.pathname = incoming.pathname.slice(BASE.length) || '/';
    destination.search = incoming.search;
    const headers = new Headers(request.headers);
    // Never forward client-supplied proxy headers; only this Worker may set them.
    for (const name of [...headers.keys()]) {
      if (name.toLowerCase().startsWith('x-pc-')) headers.delete(name);
    }
    // Dify/Neon secrets never enter this router. The Pages backend validates Origin.
    if (request.method === 'POST') headers.set('Origin', TARGET_ORIGIN);
    headers.delete('Host');

    // Signed client IP: timestamp, IP, method and backend path are bound by the HMAC (valid for 60 s).
    const clientIp = request.headers.get('CF-Connecting-IP') || '';
    const timestamp = String(Math.floor(Date.now() / 1000));
    headers.set('X-PC-Client-IP', clientIp);
    headers.set('X-PC-Timestamp', timestamp);
    headers.set('X-PC-Signature', await sign(secret, `${timestamp}\n${clientIp}\n${request.method}\n${destination.pathname}`));

    const upstream = await fetch(new Request(destination.href, { method: request.method,
      headers,
      body: request.method === 'GET' || request.method === 'HEAD' ? undefined : request.body,
      redirect: 'manual' }));
    const response = new Response(upstream.body, upstream);

    // Ensure session cookie is sent only on the Prompt Challenge subpath.
    const setCookie = upstream.headers.get('Set-Cookie');
    if (setCookie) {
      response.headers.set('Set-Cookie', setCookie.replace(/;\s*Path=\//i, '; Path=/promptchallenge/'));
    }
    // Do not cache authenticated or API responses at the router.
    if (destination.pathname.startsWith('/api/')) response.headers.set('Cache-Control', 'no-store');
    // HSTS without includeSubDomains, so other cyberactivity.com.br subdomains are not affected.
    response.headers.set('Strict-Transport-Security', 'max-age=31536000');
    response.headers.set('X-Content-Type-Options', 'nosniff');
    response.headers.set('Referrer-Policy', 'no-referrer');
    response.headers.set('X-Frame-Options', 'DENY');
    response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    if (!destination.pathname.startsWith('/api/')) {
      response.headers.set('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'");
    }
    return response;
  }
};
