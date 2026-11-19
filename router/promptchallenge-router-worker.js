// Cloudflare Worker. Route only cyberactivity.com.br/promptchallenge and /promptchallenge/*
// The existing cyberactivity.com.br site continues to handle all other paths.
const PUBLIC_ORIGIN = 'https://cyberactivity.com.br';
const TARGET_ORIGIN = 'https://promptchallenge.pages.dev';
const BASE = '/promptchallenge';

export default {
  async fetch(request) {
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

    const destination = new URL(TARGET_ORIGIN);
    destination.pathname = incoming.pathname.slice(BASE.length) || '/';
    destination.search = incoming.search;
    const headers = new Headers(request.headers);
    // Dify/Neon secrets never enter this router. The Pages backend validates Origin.
    if (request.method === 'POST') headers.set('Origin', TARGET_ORIGIN);
    headers.delete('Host');

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
    return response;
  }
};
