/**
 * server.js — Entry point backend key manager
 */
require('dotenv').config();
const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const session = require('express-session');
const flash = require('connect-flash');
const morgan = require('morgan');
const crypto = require('crypto');
const { securityHeaders } = require('./middleware/security');

const apiRoutes = require('./routes/api');
const adminRoutes = require('./routes/admin');

const app = express();
const PORT = process.env.PORT || 4000;

// ── View engine ──
app.set('view engine', 'pug');
app.set('views', path.join(__dirname, 'views'));

// ── Middleware ──
app.disable('x-powered-by');
// Đặt TRUST_PROXY (vd: 1) khi chạy sau reverse proxy / nginx để lấy đúng IP client
if (process.env.TRUST_PROXY) {
    const tp = process.env.TRUST_PROXY;
    app.set('trust proxy', /^\d+$/.test(tp) ? Number(tp) : tp);
}
app.use(morgan('dev'));
app.use(securityHeaders);
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// Session
let sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret || sessionSecret.length < 32 || sessionSecret === 'supersecretkey_changeme') {
    console.warn('⚠️  SESSION_SECRET chưa đặt hoặc quá yếu → dùng secret ngẫu nhiên (session sẽ mất khi restart)');
    sessionSecret = crypto.randomBytes(48).toString('hex');
}
app.use(session({
    name: 'km.sid',
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
        httpOnly: true,
        sameSite: 'strict',
        secure: 'auto',
        maxAge: 8 * 60 * 60 * 1000, // 8 giờ không hoạt động
    },
}));
app.use(flash());

// ── Routes ──
app.use('/api', apiRoutes);       // Public — dành cho Electron app
app.use('/admin', adminRoutes);   // Admin panel

// Redirect root → admin
app.get('/', (_req, res) => res.redirect('/admin'));

// ── 404 ──
app.use((_req, res) => {
    res.status(404).json({ ok: false, message: 'Not found' });
});

// ── Error handler (không lộ stack trace) ──
app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    if (status >= 500) console.error('[error]', err);
    res.status(status).json({ ok: false, message: status >= 500 ? 'Lỗi server' : 'Yêu cầu không hợp lệ' });
});

// ── Connect MongoDB ──
mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        console.log('✅ MongoDB connected');
        app.listen(PORT, () => {
            console.log(`🚀 Key Manager running → http://localhost:${PORT}`);
            console.log(`   Admin panel       → http://localhost:${PORT}/admin`);
            console.log(`   API verify key    → POST http://localhost:${PORT}/api/key/verify`);
            console.log(`   API activate key  → POST http://localhost:${PORT}/api/key/activate`);
        });
    })
    .catch(err => {
        console.error('❌ MongoDB connection failed:', err.message);
        process.exit(1);
    });
