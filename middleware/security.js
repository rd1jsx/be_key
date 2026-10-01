/**
 * middleware/security.js
 * Security headers (CSP có nonce), rate limit in-memory, CSRF token
 */
const crypto = require('crypto');

// ── Security headers + CSP nonce cho inline script ──
exports.securityHeaders = (req, res, next) => {
    const nonce = crypto.randomBytes(16).toString('base64');
    res.locals.nonce = nonce;
    res.setHeader('Content-Security-Policy', [
        "default-src 'self'",
        `script-src 'self' 'nonce-${nonce}'`,
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com",
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com",
        "img-src 'self' data:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ].join('; '));
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    if (req.secure) {
        res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
    }
    next();
};

// ── Rate limit đơn giản theo IP (fixed window, lưu trong RAM) ──
exports.rateLimit = ({ windowMs, max, message }) => {
    const hits = new Map();
    setInterval(() => {
        const now = Date.now();
        for (const [ip, h] of hits) if (h.resetAt <= now) hits.delete(ip);
    }, windowMs).unref();

    return (req, res, next) => {
        const now = Date.now();
        let h = hits.get(req.ip);
        if (!h || h.resetAt <= now) {
            h = { count: 0, resetAt: now + windowMs };
            hits.set(req.ip, h);
        }
        h.count++;
        if (h.count > max) {
            res.setHeader('Retry-After', Math.ceil((h.resetAt - now) / 1000));
            return res.status(429).json({ ok: false, code: 'RATE_LIMITED', message });
        }
        next();
    };
};

// ── CSRF: token gắn với session ──
exports.csrfToken = (req) => {
    if (!req.session.csrf) req.session.csrf = crypto.randomBytes(32).toString('hex');
    return req.session.csrf;
};

function safeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const ba = Buffer.from(a);
    const bb = Buffer.from(b);
    return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}
exports.safeEqual = safeEqual;

// Kiểm tra token cho mọi request thay đổi dữ liệu (header X-CSRF-Token hoặc field _csrf)
exports.verifyCsrf = (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    const token = req.get('X-CSRF-Token') || req.body?._csrf;
    if (req.session?.csrf && safeEqual(token, req.session.csrf)) return next();
    if (req.is('json') || req.get('X-CSRF-Token') !== undefined || req.method !== 'POST') {
        return res.status(403).json({ ok: false, message: 'CSRF token không hợp lệ, vui lòng tải lại trang' });
    }
    req.flash('error', 'Phiên làm việc đã hết hạn, vui lòng thử lại');
    return res.redirect('/admin/login');
};
