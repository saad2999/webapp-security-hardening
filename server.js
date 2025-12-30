require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise');
const path = require('path');
const morgan = require('morgan');
const expressLayout = require('express-ejs-layouts');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const winston = require('winston');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const validator = require('./validator');
const validatorLib = require('validator');
const ids = require('./ids');
const cors = require('cors');
const csrf = require('@dr.pogodin/csurf');

const app = express();

// ======================
// 1. SECURITY HEADERS & PROXY (Week 4 Task 3)
// ======================
app.set('trust proxy', 1); // Trust Cloud Run Load Balancer 

app.use(helmet({
    contentSecurityPolicy: { // CSP Implementation [cite: 14, 15]
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            upgradeInsecureRequests: [], // Enforce HTTPS [cite: 16]
        },
    },
    hsts: { // HSTS Enforcement [cite: 16]
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// Monitoring & Logging (Week 4 Task 1) [cite: 7, 8]
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    transports: [new winston.transports.Console()]
});

// ======================
// 2. MIDDLEWARE & API HARDENING (Week 4 Task 2)
// ======================
app.use(expressLayout);
app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

// CORS configuration 
app.use(cors({
    origin: process.env.ALLOWED_ORIGIN || false, 
    credentials: true
}));

app.use(session({
    secret: process.env.SESSION_SECRET || 'clearway-2025-secure-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 2 * 60 * 60 * 1000
    }
}));

// CSRF Protection Implementation (Week 5 Task 3) [cite: 31, 32]
const csrfProtection = csrf({
    cookie: {
        httpOnly: true, // Prevents client-side access (Fixes Burp Suite vulnerability)
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
    }
});

// Rate Limiting (Week 4 Task 2) [cite: 10, 11]
class SimpleRateLimiter {
    constructor(windowMs, max) {
        this.windowMs = windowMs;
        this.max = max;
        this.hits = new Map();
    }
    middleware() {
        return (req, res, next) => {
            const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;
            const now = Date.now();
            if (!this.hits.has(clientIp)) this.hits.set(clientIp, []);
            const hits = this.hits.get(clientIp).filter(t => t > now - this.windowMs);
            if (hits.length >= this.max) {
                logger.warn(`Rate limit exceeded for IP: ${clientIp}`); // Alert monitoring [cite: 9]
                return res.status(429).json({ error: 'Too many requests' });
            }
            hits.push(now);
            this.hits.set(clientIp, hits);
            next();
        };
    }
}
const globalLimiter = new SimpleRateLimiter(15 * 60 * 1000, 200);
app.use(globalLimiter.middleware());

// ======================
// 3. DATABASE CONFIGURATION
// ======================
const pool = mysql.createPool({
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'Clearway_Cyber_db',
    socketPath: process.env.INSTANCE_CONNECTION_NAME ? `/cloudsql/${process.env.INSTANCE_CONNECTION_NAME}` : undefined,
    host: process.env.DB_HOST || '127.0.0.1',
    waitForConnections: true,
    connectionLimit: 10
});

// ======================
// 4. SECURED ROUTES (Week 5 Task 2 & 3)
// ======================

app.use((req, res, next) => {
    const token = req.cookies?.token;
    if (token) {
        try {
            const payload = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret');
            res.locals.user = payload.user;
            req.user = payload.user;
        } catch (e) { logger.debug('JWT Verification Failed'); }
    }
    next();
});

app.get('/', (req, res) => res.render('index'));
app.get('/login', (req, res) => res.render('login'));
app.get('/signup', csrfProtection, (req, res) => res.render('signup', { csrfToken: req.csrfToken() }));
app.get('/profile', csrfProtection, (req, res) => {
    if (!req.user) return res.redirect('/login');
    res.render('profile', { user: req.user, csrfToken: req.csrfToken() });
});

// SECURE UPDATE BIO (SQLi & CSRF Protected) [cite: 30, 32]
app.post('/update-bio', csrfProtection, ids.idsMiddleware, async (req, res) => {
    if (!req.user) return res.status(401).send('Unauthorized');
    const { bio } = req.body;
    const bioCheck = validator.validateBio(bio);
    if (!bioCheck.ok) return res.redirect('/profile?error=Invalid bio');

    try {
        // PREPARED STATEMENT Prevents SQLi 
        await pool.execute('UPDATE users SET bio = ? WHERE id = ?', [bioCheck.sanitized, req.user.id]);
        res.redirect('/profile?success=Bio updated');
    } catch (error) {
        logger.error('Bio Update Error', error);
        res.redirect('/profile?error=Update failed');
    }
});

// SECURE CHANGE PASSWORD (SQLi & CSRF Protected) [cite: 30, 32]
app.post('/change-password', csrfProtection, ids.idsMiddleware, async (req, res) => {
    if (!req.user) return res.status(401).send('Unauthorized');
    const { newPassword } = req.body;
    const pwdCheck = validator.validatePassword(newPassword);
    if (!pwdCheck.ok) return res.redirect('/profile?error=Weak password');

    try {
        const pepper = process.env.PEPPER || 'ClearwayCyberHardenedPepper2025';
        const hashed = await bcrypt.hash(newPassword + pepper, 12);
        // PREPARED STATEMENT Prevents SQLi 
        await pool.execute('UPDATE users SET password = ? WHERE id = ?', [hashed, req.user.id]);
        res.redirect('/profile?success=Password changed');
    } catch (error) {
        logger.error('Password Change Error', error);
        res.redirect('/profile?error=Failed to change password');
    }
});

// Health check endpoint for Cloud Run
app.get('/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        res.status(200).json({ status: 'healthy' });
    } catch (e) { res.status(503).json({ status: 'unhealthy' }); }
});

// ======================
// 5. STARTUP
// ======================
const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
    logger.info(`🚀 CLEARWAY CYBER SECURED - Port ${PORT}`);
});