require('dotenv').config();
const express = require('express');

const session = require('express-session');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const path = require('path');
const morgan = require('morgan');
const expressLayout = require('express-ejs-layouts');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const validator = require('./validator');
const validatorLib = require('validator');
const ids = require('./ids');
const cors = require('cors');
const csrf = require('@dr.pogodin/csurf');

const app = express();

// Layouts and views
app.use(expressLayout);
app.set('layout', 'layout');
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(morgan('dev'));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static('public'));

// Session with secure config
app.use(session({
    secret: process.env.SESSION_SECRET || 'clearway-2025-fallback-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
    }
}));

app.use(cookieParser());

// CORS
app.use(cors({
    origin: process.env.ALLOWED_ORIGIN || 'http://localhost:3000',
    credentials: true,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}));

// Helmet with CSP + HSTS
app.use(helmet({
    contentSecurityPolicy: {
        useDefaults: true,
        directives: {
            "default-src": ["'self'"],
            "script-src": ["'self'", "https:"],
            "style-src": ["'self'", "https:", "'unsafe-inline'"],
            "img-src": ["'self'", "data:", "https:"],
            "connect-src": ["'self'"],
            "frame-ancestors": ["'none'"]
        }
    },
    hsts: {
        maxAge: 63072000,
        includeSubDomains: true,
        preload: true
    }
}));

// CSRF Protection
const csrfProtection = csrf({
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
    }
});

// Smart CSRF middleware
app.use((req, res, next) => {
    if (req.path === '/login' && req.headers['content-type'] === 'application/json') {
        return next();
    }

    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return csrfProtection(req, res, (err) => {
            if (!err && typeof req.csrfToken === 'function') {
                try {
                    res.locals.csrfToken = req.csrfToken();
                } catch (e) { /* ignore */ }
            }
            next();
        });
    }

    return csrfProtection(req, res, next);
});

// Rate limiting
const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200, standardHeaders: true, legacyHeaders: false });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false });
app.use(globalLimiter);

// Health check – shows DB status
app.get('/health', (req, res) => {
    const dbStatus = (db && db.state === 'authenticated') ? 'connected' : 'disconnected';
    res.json({ status: 'ok', time: Date.now(), database: dbStatus });
});

// Winston Logger
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
            const metaStr = Object.keys(meta).length ? JSON.stringify(meta) : '';
            return `${timestamp} [${level}] ${message} ${metaStr}`;
        })
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'security.log' }),
        new winston.transports.File({ filename: 'alerts.log', level: 'warn' })
    ]
});
app.set('logger', logger);

// Secrets
const PEPPER = process.env.PEPPER || 'ClearwayCyberHardenedPepper2025DoNotShare!@#';
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-jwt-secret-2025-change-in-production';
const SALT_ROUNDS = 12;

// Auth middleware
app.use((req, res, next) => {
    res.locals.error = req.query.error;
    res.locals.success = req.query.success;
    res.locals.user = null;

    const token = req.cookies?.token || req.headers.authorization?.split(' ')[1];
    if (token) {
        try {
            const payload = jwt.verify(token, JWT_SECRET);
            res.locals.user = payload.user;
            req.user = payload.user;
        } catch (e) { /* invalid token */ }
    } else if (req.session?.user) {
        res.locals.user = req.session.user;
        req.user = req.session.user;
    }

    next();
});

// Database Connection – NON-FATAL for Cloud Run
const db = mysql.createConnection({
    host: process.env.DB_HOST || '127.0.0.1',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'Clearway_Cyber_db'
});

db.connect(err => {
    if (err) {
        logger.warn("Initial DB connection failed – retrying on queries (normal during Cloud Run startup)", { 
            error: err.message || err 
        });
        // NEVER exit – Cloud Run sidecar proxy may not be ready yet
    } else {
        logger.info("DB Connected Successfully on startup");
    }
});

// Safe query wrapper with retry logic for transient startup issues
const safeQuery = (sql, params, callback, retries = 3) => {
    db.query(sql, params, (err, results) => {
        if (err && retries > 0 && ['ECONNRESET', 'ETIMEDOUT', 'PROTOCOL_CONNECTION_LOST'].includes(err.code)) {
            logger.warn(`Transient DB error – retrying ${retries} more times`, { code: err.code });
            setTimeout(() => safeQuery(sql, params, callback, retries - 1), 1000);
            return;
        }
        if (err) {
            logger.error("DB query failed", { sql: sql.substring(0, 100), error: err.message });
        }
        callback(err, results || []);
    });
};

// Routes
app.get('/', (req, res) => res.render('index'));
app.get('/login', (req, res) => res.render('login'));
app.get('/signup', (req, res) => res.render('signup'));

app.get('/profile', (req, res) => {
    if (!res.locals.user) return res.redirect('/login');
    res.render('profile');
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    req.session.destroy(() => {});
    res.redirect('/');
});

// Login
app.post('/login', loginLimiter, async (req, res) => {
    try {
        const { email = '', password = '' } = req.body;
        if (!validatorLib.isEmail(String(email)) || !password) {
            return res.redirect('/login?error=Invalid%20login');
        }

        safeQuery('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
            if (err || results.length === 0) {
                logger.warn(`FAILED_LOGIN email=${email} ip=${req.ip} reason=no_user_or_db_error`);
                return res.redirect('/login?error=Invalid%20login');
            }
            const user = results[0];
            const ok = await bcrypt.compare(password + PEPPER, user.password);
            if (!ok) {
                logger.warn(`FAILED_LOGIN email=${email} ip=${req.ip} reason=wrong_password`);
                return res.redirect('/login?error=Invalid%20login');
            }
            logger.info(`SUCCESSFUL_LOGIN email=${email} ip=${req.ip}`);

            const payloadUser = { id: user.id, email: user.email, name: user.name, bio: user.bio };
            const token = jwt.sign({ user: payloadUser }, JWT_SECRET, { expiresIn: '2h' });
            res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' });
            req.session.user = payloadUser;
            res.redirect('/profile');
        });
    } catch (e) {
        logger.error("Login exception", { error: e.message });
        res.redirect('/login?error=Server%20error');
    }
});

// Signup
app.post('/signup', ids.idsMiddleware, csrfProtection, async (req, res) => {
    try {
        let { email, password, name, bio = '' } = req.body;
        if (!email || !password) return res.redirect('/signup?error=Missing%20fields');
        if (!validatorLib.isEmail(email)) return res.redirect('/signup?error=Invalid%20email');

        const pwdCheck = validator.validatePassword(password);
        if (!pwdCheck.ok) return res.redirect('/signup?error=Weak%20password');

        name = validatorLib.escape(name || '');
        bio = validatorLib.escape(bio);

        const hashed = await bcrypt.hash(password + PEPPER, SALT_ROUNDS);

        safeQuery('INSERT INTO users (email, password, name, bio) VALUES (?, ?, ?, ?)', [email, hashed, name, bio], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.redirect('/signup?error=Email%20exists');
                }
                logger.error("Signup failed", { error: err.message });
                return res.redirect('/signup?error=Service%20temporarily%20unavailable');
            }
            logger.info(`New user registered: ${email}`);
            res.redirect('/login?success=Account%20created');
        });
    } catch (e) {
        logger.error("Signup exception", { error: e.message });
        res.redirect('/signup?error=Server%20error');
    }
});

// Update Bio
app.post('/update-bio', ids.idsMiddleware, csrfProtection, (req, res) => {
    const user = res.locals.user;
    if (!user) return res.redirect('/login');

    const rawBio = req.body.bio || '';
    const bioCheck = validator.validateBio(rawBio);
    if (!bioCheck.ok) return res.redirect('/profile?error=Invalid%20bio');

    safeQuery('UPDATE users SET bio = ? WHERE id = ?', [bioCheck.sanitized, user.id], (err) => {
        if (err) {
            logger.warn("Bio update failed", { error: err.message });
            return res.redirect('/profile?error=Update%20failed');
        }

        const updatedUser = { ...user, bio: bioCheck.sanitized };
        req.session.user = updatedUser;
        const token = jwt.sign({ user: updatedUser }, JWT_SECRET, { expiresIn: '2h' });
        res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' });

        res.redirect('/profile?success=Bio%20updated');
    });
});

// Change Password
app.post('/change-password', ids.idsMiddleware, csrfProtection, async (req, res) => {
    const user = res.locals.user;
    if (!user) return res.redirect('/login');

    const newPassword = req.body.newPassword;
    const pwdCheck = validator.validatePassword(newPassword);
    if (!pwdCheck.ok) return res.redirect('/profile?error=Weak%20password');

    const hashed = await bcrypt.hash(newPassword + PEPPER, SALT_ROUNDS);
    safeQuery('UPDATE users SET password = ? WHERE id = ?', [hashed, user.id], (err) => {
        if (err) {
            logger.warn("Password change failed", { error: err.message });
            return res.redirect('/profile?error=Password%20change%20failed');
        }
        res.redirect('/profile?success=Password%20changed');
    });
});

// API Endpoints
function requireAuthApi(req, res, next) {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        req.user = payload.user;
        next();
    } catch (e) {
        res.status(401).json({ error: 'Invalid token' });
    }
}

app.get('/api/profile', requireAuthApi, (req, res) => {
    res.json({ user: req.user });
});

app.post('/api/update-bio', requireAuthApi, (req, res) => {
    const csrfToken = req.headers['x-csrf-token'] || req.body._csrf;
    if (!csrfToken || !req.csrfToken || csrfToken !== req.csrfToken()) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }

    const rawBio = req.body.bio || '';
    const bioCheck = validator.validateBio(rawBio);
    if (!bioCheck.ok) return res.status(400).json({ error: 'Invalid bio' });

    safeQuery('UPDATE users SET bio = ? WHERE id = ?', [bioCheck.sanitized, req.user.id], (err) => {
        if (err) return res.status(500).json({ error: 'Update failed' });
        const updatedUser = { ...req.user, bio: bioCheck.sanitized };
        const newToken = jwt.sign({ user: updatedUser }, JWT_SECRET, { expiresIn: '2h' });
        res.json({ success: true, user: updatedUser, token: newToken });
    });
});

// Start server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    logger.info('CLEARWAY CYBER - WEEK 5 COMPLETE: SQLi & CSRF PROTECTED......');
    logger.info(`Server running at http://localhost:${PORT}`);
    logger.info('CSRF tokens required on all state-changing requests.');
    logger.info('Ready for Burp Suite testing and ethical hacking report.');
});