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

const apiRoutes = require('./routes/api');
const adminRoutes = require('./routes/admin');

const app = express();
const PORT = process.env.PORT || 4000;

// ── View engine ──
app.set('view engine', 'pug');
app.set('views', path.join(__dirname, 'views'));

// ── Middleware ──
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session
app.use(session({
    secret: process.env.SESSION_SECRET || 'dev_secret_key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }, // 1 ngày
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
