/**
 * Middleware xác thực admin
 * - Mật khẩu lưu dạng hash scrypt (ADMIN_PASS_HASH), không lưu plaintext
 * - Khoá đăng nhập tạm thời khi sai nhiều lần
 */
const crypto = require('crypto');
const { safeEqual } = require('./security');

// Hash scrypt của mật khẩu admin. Có thể ghi đè bằng biến môi trường ADMIN_PASS_HASH
// (tạo hash mới: node -e "const c=require('crypto');const s=c.randomBytes(16);console.log('scrypt\$'+s.toString('hex')+'\$'+c.scryptSync('MAT_KHAU',s,64).toString('hex'))")
const DEFAULT_PASS_HASH = 'scrypt$64b2305a582eaf093e91750822161b61$75e7682b95240f28f3666ff0c415d78030dc63ba3ebefc97ad09ae26403d3793402041f64820b15210432181eacdc682d21462fbd4c30a19b0c3da1c6ecf0502';

const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS_HASH = process.env.ADMIN_PASS_HASH || DEFAULT_PASS_HASH;

function verifyPassword(password, stored) {
    const [algo, saltHex, hashHex] = stored.split('$');
    if (algo !== 'scrypt' || !saltHex || !hashHex) return false;
    const expected = Buffer.from(hashHex, 'hex');
    const actual = crypto.scryptSync(String(password), Buffer.from(saltHex, 'hex'), expected.length);
    return crypto.timingSafeEqual(actual, expected);
}

exports.checkCredentials = (username, password) => {
    if (typeof username !== 'string' || typeof password !== 'string') return false;
    if (password.length > 256) return false;
    // Luôn chạy scrypt để không lộ thông tin qua thời gian phản hồi
    const passOk = verifyPassword(password, ADMIN_PASS_HASH);
    return safeEqual(username, ADMIN_USER) && passOk;
};

// ── Khoá đăng nhập: 5 lần sai / 15 phút theo IP ──
const MAX_FAILS = 5;
const LOCK_MS = 15 * 60 * 1000;
const fails = new Map();

exports.loginLockedFor = (ip) => {
    const f = fails.get(ip);
    if (!f) return 0;
    if (f.until && f.until > Date.now()) return Math.ceil((f.until - Date.now()) / 60000);
    if (f.until) fails.delete(ip);
    return 0;
};

exports.recordLoginFail = (ip) => {
    const f = fails.get(ip) || { count: 0, until: 0 };
    f.count++;
    if (f.count >= MAX_FAILS) {
        f.until = Date.now() + LOCK_MS;
        f.count = 0;
    }
    fails.set(ip, f);
};

exports.clearLoginFails = (ip) => fails.delete(ip);

exports.requireAdmin = (req, res, next) => {
    if (req.session && req.session.isAdmin) return next();
    // Nếu là API request → trả 401
    if (req.path.startsWith('/api')) {
        return res.status(401).json({ ok: false, message: 'Chưa đăng nhập admin' });
    }
    return res.redirect('/admin/login');
};
