export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // مسیرهای مجاز (اینجا اضافه/حذف کن)
    const allowedPaths = ['/dns-query', '/custom-path'];

    if (!allowedPaths.includes(path)) {
      return new Response('Not Found', { status: 404 });
    }

    // محدودیت اندازه (مثلاً 64KB)
    const MAX_BODY_BYTES = 64 * 1024;

    // helper: base64url -> ArrayBuffer
    function base64UrlToArrayBuffer(b64u) {
      // تبدیل base64url به base64
      b64u = b64u.replace(/-/g, '+').replace(/_/g, '/');
      // padding
      while (b64u.length % 4) b64u += '=';
      const binary = atob(b64u);
      const len = binary.length;
      const bytes = new Uint8Array(len);
      for (let i = 0; i < len; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes.buffer;
    }

    // helper: محدود کردن buffer size
    async function readBodyLimited(req, maxBytes) {
      const reader = req.body?.getReader?.();
      if (!reader) {
        // no body (e.g. GET)
        return new ArrayBuffer(0);
      }
      const chunks = [];
      let received = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
        if (received > maxBytes) {
          throw new Error('PayloadTooLarge');
        }
        chunks.push(value);
      }
      // concat
      const out = new Uint8Array(received);
      let offset = 0;
      for (const c of chunks) {
        out.set(c, offset);
        offset += c.byteLength;
      }
      return out.buffer;
    }

    // خواندن payload براساس متد
    let dnsRequestBuffer;
    try {
      if (request.method === 'POST') {
        const ct = request.headers.get('content-type') || '';
        if (!ct.includes('application/dns-message')) {
          return new Response('Unsupported Media Type', { status: 415 });
        }
        dnsRequestBuffer = await readBodyLimited(request, MAX_BODY_BYTES);
      } else if (request.method === 'GET') {
        // استاندارد DoH (RFC 8484): query parameter "dns" contains base64url of wire-format DNS message
        const dnsParam = url.searchParams.get('dns');
        if (!dnsParam) {
          return new Response('Bad Request: missing dns query parameter', { status: 400 });
        }
        try {
          dnsRequestBuffer = base64UrlToArrayBuffer(dnsParam);
          if (dnsRequestBuffer.byteLength > MAX_BODY_BYTES) throw new Error('PayloadTooLarge');
        } catch (e) {
          return new Response('Bad Request: invalid dns param', { status: 400 });
        }
      } else {
        return new Response('Method Not Allowed', { status: 405 });
      }
    } catch (err) {
      if (err.message === 'PayloadTooLarge') {
        return new Response('Payload Too Large', { status: 413 });
      }
      return new Response('Bad Request', { status: 400 });
    }

    // fetch به upstream (Cloudflare DNS) با تایم‌اوت
    const upstream = 'https://cloudflare-dns.com/dns-query';
    const TIMEOUT_MS = 5000; // قابل تغییر

    try {
      const controller = new AbortController();
      const id = setTimeout(() => controller.abort(), TIMEOUT_MS);

      const resp = await fetch(upstream, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/dns-message',
          'Accept': 'application/dns-message',
          // می‌تونی هدرهای دیگری هم اینجا قرار بدی در صورت نیاز
        },
        body: dnsRequestBuffer,
        signal: controller.signal
      });

      clearTimeout(id);

      // اگر upstream خطا داد
      if (!resp.ok) {
        // کد 502 برای خطای گیت‌وی
        return new Response('Bad Gateway', { status: 502 });
      }

      // خواندن پاسخ (نه خیلی بزرگ)
      const dnsResponse = await resp.arrayBuffer();

      // انتقال هدرهای مفید (مثلاً Cache-Control از upstream)
      const headers = {
        'Content-Type': 'application/dns-message',
        // CORS: اگر قصد استفاده از مرورگر داری ممکنه لازم باشه
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Accept',
        // انتقال یا تعیین Cache-Control: اگر upstream هدر داره از آن استفاده کن، در غیر اینصورت TTL پیشفرض
        'Cache-Control': resp.headers.get('Cache-Control') || 'no-cache, no-store, max-age=0',
      };

      return new Response(dnsResponse, { status: 200, headers });
    } catch (err) {
      if (err.name === 'AbortError') {
        return new Response('Gateway Timeout', { status: 504 });
      }
      // لو نده خطای داخلی
      return new Response('Internal Server Error', { status: 500 });
    }
  },

  // پشتیبانی از preflight CORS (اختیاری، برای مرورگر)
  async options(request, env, ctx) {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Accept',
        'Access-Control-Max-Age': '86400'
      }
    });
  }
};
