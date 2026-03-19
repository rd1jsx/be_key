/**
 * Middleware xác thực admin session đơn giản
 * (dùng biến môi trường ADMIN_USER / ADMIN_PASS)
 */
exports.requireAdmin = (req, res, next) => {
    if (req.session && req.session.isAdmin) return next();
    // Nếu là API request → trả 401
    if (req.path.startsWith('/api')) {
        return res.status(401).json({ ok: false, message: 'Chưa đăng nhập admin' });
    }
    return res.redirect('/admin/login');
};
