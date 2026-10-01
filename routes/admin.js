/**
 * routes/admin.js
 * Routes cho trang quản trị (admin panel)
 * Base: /admin
 */
const express = require('express');
const router = express.Router();
const ctrl = require('../controllers/keyController');
const Key = require('../models/Key');
const auth = require('../middleware/auth');
const { requireAdmin } = auth;
const { csrfToken, verifyCsrf } = require('../middleware/security');

// Token CSRF cho mọi view
router.use((req, res, next) => {
    res.locals.csrfToken = csrfToken(req);
    next();
});
router.use(verifyCsrf);

// ── Auth ──
router.get('/login', (req, res) => {
    if (req.session?.isAdmin) return res.redirect('/admin');
    res.render('admin/login', { error: req.flash('error') });
});

router.post('/login', (req, res) => {
    const lockedMin = auth.loginLockedFor(req.ip);
    if (lockedMin) {
        req.flash('error', `Đăng nhập sai quá nhiều lần. Thử lại sau ${lockedMin} phút`);
        return res.redirect('/admin/login');
    }

    const { username, password } = req.body;
    if (!auth.checkCredentials(username, password)) {
        auth.recordLoginFail(req.ip);
        console.warn(`[login] Đăng nhập thất bại từ IP ${req.ip}`);
        req.flash('error', 'Sai tài khoản hoặc mật khẩu');
        return res.redirect('/admin/login');
    }

    auth.clearLoginFails(req.ip);
    // Tạo session mới để chống session fixation
    req.session.regenerate(err => {
        if (err) {
            req.flash('error', 'Không tạo được phiên đăng nhập');
            return res.redirect('/admin/login');
        }
        req.session.isAdmin = true;
        req.session.save(() => res.redirect('/admin'));
    });
});

router.post('/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('km.sid');
        res.redirect('/admin/login');
    });
});

// ── Dashboard (trang chính) ──
router.get('/', requireAdmin, async (req, res) => {
    try {
        const keys = await Key.find().sort({ createdAt: -1 }).lean();
        res.render('admin/index', {
            keys,
            success: req.flash('success'),
            error: req.flash('error'),
        });
    } catch (err) {
        console.error('[dashboard]', err);
        res.render('admin/index', { keys: [], error: ['Không tải được danh sách key'], success: null });
    }
});

// ── REST API (dùng từ trang admin AJAX) ──
router.get('/api/keys', requireAdmin, ctrl.listKeys);
router.post('/api/keys', requireAdmin, ctrl.createKey);
router.put('/api/keys/:id', requireAdmin, ctrl.updateKey);
router.delete('/api/keys/:id', requireAdmin, ctrl.deleteKey);
router.delete('/api/keys/:id/devices/:deviceId', requireAdmin, ctrl.removeDevice);
router.delete('/api/keys/:id/devices', requireAdmin, ctrl.resetDevices);

module.exports = router;
