/**
 * routes/api.js
 * Public API dành cho Electron app
 * Base: /api
 */
const express = require('express');
const router = express.Router();
const ctrl = require('../controllers/keyController');
const { rateLimit } = require('../middleware/security');

// Chống dò key: tối đa 30 request / phút / IP
router.use(rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    message: 'Quá nhiều yêu cầu, vui lòng thử lại sau',
}));

// POST /api/key/verify  — Check lần 1: nhập key
router.post('/key/verify', ctrl.verifyKey);

// POST /api/key/activate — Check lần 2: bấm Start (đăng ký device)
router.post('/key/activate', ctrl.activateKey);

module.exports = router;
