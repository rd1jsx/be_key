/**
 * routes/api.js
 * Public API dành cho Electron app
 * Base: /api
 */
const express = require('express');
const router = express.Router();
const ctrl = require('../controllers/keyController');

// POST /api/key/verify  — Check lần 1: nhập key
router.post('/key/verify', ctrl.verifyKey);

// POST /api/key/activate — Check lần 2: bấm Start (đăng ký device)
router.post('/key/activate', ctrl.activateKey);

module.exports = router;
