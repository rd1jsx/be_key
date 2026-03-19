/**
 * routes/admin.js
 * Routes cho trang quản trị (admin panel)
 * Base: /admin
 */
const express = require('express');
const router = express.Router();
const ctrl = require('../controllers/keyController');
const { requireAdmin } = require('../middleware/auth');

// ── Auth ──
router.get('/login', (req, res) => {
    if (req.session?.isAdmin) return res.redirect('/admin');
    res.render('admin/login', { error: req.flash('error') });
});

router.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (
        username === process.env.ADMIN_USER &&
        password === process.env.ADMIN_PASS
    ) {
        req.session.isAdmin = true;
        return res.redirect('/admin');
    }
    req.flash('error', 'Sai tài khoản hoặc mật khẩu');
    res.redirect('/admin/login');
});

router.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/admin/login'));
});

// ── Dashboard (trang chính) ──
router.get('/', requireAdmin, async (req, res) => {
    const Key = require('../models/Key');
    try {
        const keys = await Key.find().sort({ createdAt: -1 }).lean();
        res.render('admin/index', {
            keys,
            success: req.flash('success'),
            error: req.flash('error'),
        });
    } catch (err) {
        res.render('admin/index', { keys: [], error: err.message, success: null });
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
