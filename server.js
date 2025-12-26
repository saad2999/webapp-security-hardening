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

const app = express();

// MUST BE BEFORE view engine
app.use(expressLayout);

app.set('layout', 'layout');
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(morgan('dev'));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static('public'));
app.use(session({
    secret: 'clearway-2025',
    resave: false,
    saveUninitialized: true
}));

// cookie parser (for reading token cookie)
app.use(cookieParser());

// Helmet secures HTTP headers
app.use(helmet.strictTransportSecurity({
    maxAge: 63072000,        // 2 years recommended for strong security
    includeSubDomains: true,
    preload: true            // If you plan to submit to hstspreload.org
}));

// Content Security Policy: conservative defaults, adjust as needed for your app
app.use(helmet.contentSecurityPolicy({
    useDefaults: true,
    directives: {
        // keep default directives but allow styles/scripts from self
        "default-src": ["'self'"],
        "script-src": ["'self'", "https:"],
        "style-src": ["'self'", "https:", "'unsafe-inline'"],
        "img-src": ["'self'", "data:", "https:"],
        "connect-src": ["'self'"],
        "frame-ancestors": ["'none'"]
    }
}));

// Simple in-memory account lockout tracker (keep in-memory -> ephemeral)
const failedLoginAttempts = new Map();
const MAX_FAILED = 5; // lock after 5 failed attempts
const LOCK_MINUTES = 15; // lockout duration

function isLocked(email) {
    const record = failedLoginAttempts.get(email);
    if (!record) return false;
    if (record.lockedUntil && Date.now() < record.lockedUntil) return true;
    return false;
}

function recordFailedAttempt(email) {
    let record = failedLoginAttempts.get(email) || { count: 0 };
    record.count = (record.count || 0) + 1;
    record.lastAttempt = Date.now();
    if (record.count >= MAX_FAILED) {
        record.lockedUntil = Date.now() + LOCK_MINUTES * 60 * 1000;
        logger.warn('Account locked due to repeated failed logins', { email, lockedUntil: record.lockedUntil });
    }
    failedLoginAttempts.set(email, record);
}

function resetFailedAttempts(email) {
    failedLoginAttempts.delete(email);
}

// Rate limiting
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 200, // limit each IP to 200 requests per windowMs
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        logger.warn('Global rate limit exceeded', { ip: req.ip });
        res.status(429).send('Too many requests, please try again later.');
    }
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10, // allow some attempts per IP window
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        logger.warn('Too many login attempts from IP', { ip: req.ip });
        res.status(429).redirect('/login?error=Too+many+requests');
    }
});

app.use(globalLimiter);

// health endpoint for monitoring
app.get('/health', (req, res) => {
    res.json({ status: 'ok', time: Date.now() });
});

// Winston logger setup
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

// expose logger on app for IDS to use
app.set('logger', logger);

// SECURITY CONFIG: pepper and JWT secret. Replace these with secure env vars in production.
const PEPPER = process.env.PEPPER || 'pepper2';
const JWT_SECRET = process.env.JWT_SECRET || 'jwt-secret';
const SALT_ROUNDS = 12;

app.use((req, res, next) => {
    res.locals.error = req.query.error;
    res.locals.user = null;

    // Prefer JWT in cookie, fall back to session for compatibility
    const token = req.cookies && req.cookies.token;
    if (token) {
        try {
            const payload = jwt.verify(token, JWT_SECRET);
            res.locals.user = payload.user;
            req.user = payload.user;
        } catch (e) {
            // invalid token - ignore and continue (user remains null)
        }
    } else if (req.session && req.session.user) {
        res.locals.user = req.session.user;
        req.user = req.session.user;
    }

    next();
});

const db = mysql.createConnection({
    host: 'localhost',
    user: 'redhat',
    password: '',
    database: 'Clearway_Cyber_db'
});

db.connect(err => {
    if (err) {
        logger.error("DB connect failed. Run: mysql -u redhat < database.sql", { error: err && err.message });
        process.exit(1);
    }
    logger.info("DB Connected");
});

// ROUTES
app.get('/', (req, res) => res.render('index'));
app.get('/login', (req, res) => res.render('login'));
app.get('/signup', (req, res) => res.render('signup'));
app.get('/profile', (req, res) => {
    // require logged-in user (from JWT cookie or session)
    if (!res.locals.user) return res.redirect('/login');
    res.render('profile');
});

app.get('/logout', (req, res) => {
    // clear token cookie and destroy session for compatibility
    res.clearCookie('token');
    if (req.session) req.session.destroy(() => { /* ignore errors */ });
    res.redirect('/');
});

app.post('/login', loginLimiter, async (req, res) => {
    try {
        const { email = '', password = '' } = req.body;
        // use validator library for email check
        if (!validatorLib.isEmail(String(email)) || !password) return res.redirect('/login?error=Invalid%20login');
        if (isLocked(email)) {
            logger.warn('Login attempt to locked account', { email, ip: req.ip });
            return res.redirect('/login?error=Account%20locked');
        }
        // fetch user by email, then compare hashed password
        db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
            if (err || results.length === 0) {
                // record failed attempt (possible invalid email)
                try { recordFailedAttempt(email); } catch (e) { }
                logger.warn('Invalid login (no such user or db error)', { email, ip: req.ip });
                // compact line for external IDS (Fail2Ban)
                logger.warn(`FAILED_LOGIN email=${email} ip=${req.ip} reason=nosuchuser`);
                return res.redirect('/login?error=Invalid%20login');
            }
            const user = results[0];
            try {
                const ok = await bcrypt.compare(password + PEPPER, user.password);
                if (!ok) {
                    recordFailedAttempt(email);
                    logger.warn('Invalid login (bad password)', { email, ip: req.ip });
                    // compact line for Fail2Ban
                    logger.warn(`FAILED_LOGIN email=${email} ip=${req.ip} reason=badpassword`);
                    return res.redirect('/login?error=Invalid%20login');
                }
                // successful login, reset failed attempts
                resetFailedAttempts(email);
                // compact success line
                logger.info(`SUCCESSFUL_LOGIN email=${email} ip=${req.ip}`);
                const payloadUser = { id: user.id, email: user.email, name: user.name, bio: user.bio };
                const token = jwt.sign({ user: payloadUser }, JWT_SECRET, { expiresIn: '2h' });
                // set httpOnly cookie for web app; secure in production
                res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' });
                // keep session for compatibility with existing views
                req.session.user = payloadUser;
                logger.info('User logged in', { userId: payloadUser.id, email: payloadUser.email, ip: req.ip });
                res.redirect('/profile');
            } catch (e) {
                logger.error('Error during login flow', { error: e && e.message, email, ip: req.ip });
                return res.redirect('/login?error=Invalid%20login');
            }
        });
    } catch (e) {
        return res.redirect('/login?error=Invalid%20login');
    }
});

app.post('/signup', ids.idsMiddleware, async (req, res) => {
    try {
        let { email, password, name, bio } = req.body;
        if (!email || !password) return res.redirect('/signup?error=Missing%20fields');
        // validate inputs with validator library and custom checks
        if (!validatorLib.isEmail(String(email))) return res.redirect('/signup?error=Invalid%20email');
        const pwdCheck = validator.validatePassword(password);
        const nameCheck = validator.validateName(name || '');
        const bioCheck = validator.validateBio(bio || '');
        if (!pwdCheck.ok) return res.redirect('/signup?error=Weak%20password');
        if (!nameCheck.ok) return res.redirect('/signup?error=Invalid%20name');
        if (!bioCheck.ok) return res.redirect('/signup?error=Invalid%20bio');
        // sanitize fields to store/render
        name = validatorLib.escape(String(name || ''));
        bio = validatorLib.escape(String(bioCheck.sanitized || ''));
        // hash password with bcrypt + pepper
        const hashed = await bcrypt.hash(password + PEPPER, SALT_ROUNDS);
        db.query('INSERT INTO users (email, password, name, bio) VALUES (?, ?, ?, ?)', [email, hashed, name, bio], (err) => {
            if (err) return res.redirect('/signup?error=Email%20exists');
            res.redirect('/login');
        });
    } catch (e) {
        return res.redirect('/signup?error=Server%20error');
    }
});

app.post('/update-bio', ids.idsMiddleware, (req, res) => {
    // require authenticated user
    const currentUser = res.locals.user || req.session.user;
    if (!currentUser) return res.redirect('/login');
    const rawBio = req.body.bio || '';
    const bioCheck = validator.validateBio(rawBio);
    if (!bioCheck.ok) return res.redirect('/profile?error=Invalid%20bio');
    const bio = bioCheck.sanitized;
    const id = currentUser.id;
    db.query('UPDATE users SET bio = ? WHERE id = ?', [bio, id], (err) => {
        if (err) logger.error('Failed to update bio', { error: err && err.message, userId: id });
        // update server-side user state and refresh token
        const updatedUser = { id: currentUser.id, email: currentUser.email, name: currentUser.name, bio };
        req.session.user = updatedUser;
        const token = jwt.sign({ user: updatedUser }, JWT_SECRET, { expiresIn: '2h' });
        res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' });
        logger.info('User bio updated', { userId: updatedUser.id, email: updatedUser.email, bioLength: (updatedUser.bio || '').length });
        res.redirect('/profile?success=Bio+updated');
        logger.info('bio updated', { userId: id });
    });
});

// CHANGE PASSWORD (PLAINTEXT VULNERABLE)
app.post('/change-password', ids.idsMiddleware, async (req, res) => {
    try {
        const currentUser = res.locals.user || req.session.user;
        if (!currentUser) return res.redirect('/login');
        const newPassword = req.body.newPassword;
        const pwdCheck = validator.validatePassword(newPassword);
        if (!pwdCheck.ok) return res.redirect('/profile?error=Weak%20password');
        const id = currentUser.id;
        const hashed = await bcrypt.hash(newPassword + PEPPER, SALT_ROUNDS);
        db.query('UPDATE users SET password = ? WHERE id = ?', [hashed, id], (err) => {
            if (err) logger.error('Failed to update password', { error: err && err.message, userId: id });
            // don't store password in session; keep other user fields
            res.redirect('/profile?success=Password+changed');
        });
    } catch (e) {
        logger.error('Error in change-password handler', { error: e && e.message });
        return res.redirect('/profile?error=Server+error');
    }
});
app.listen(3000, () => {
    logger.info('\nCLEARWAY CYBER - WEEK 1 FINAL - 100% WORKING');
    logger.info('http://localhost:3000');
    logger.info("SQLi: admin@clearway.com' OR '1'='1");
    logger.info('XSS: <script>alert("HIRED")</script>');
});
