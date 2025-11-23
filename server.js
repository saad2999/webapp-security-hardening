const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
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
app.use(helmet());

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
        new winston.transports.File({ filename: 'security.log' })
    ]
});

// SECURITY CONFIG: pepper and JWT secret. Replace these with secure env vars in production.
const PEPPER = process.env.PEPPER || 'please-change-this-pepper';
const JWT_SECRET = process.env.JWT_SECRET || 'please-change-this-jwt-secret';
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

app.post('/login', async (req, res) => {
    try {
        const { email = '', password = '' } = req.body;
        // use validator library for email check
        if (!validatorLib.isEmail(String(email)) || !password) return res.redirect('/login?error=Invalid%20login');
        // fetch user by email, then compare hashed password
        db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
            if (err || results.length === 0) {
                return res.redirect('/login?error=Invalid%20login');
            }
            const user = results[0];
            try {
                const ok = await bcrypt.compare(password + PEPPER, user.password);
                if (!ok) return res.redirect('/login?error=Invalid%20login');
                const payloadUser = { id: user.id, email: user.email, name: user.name, bio: user.bio };
                const token = jwt.sign({ user: payloadUser }, JWT_SECRET, { expiresIn: '2h' });
                // set httpOnly cookie for web app; secure in production
                res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' });
                // keep session for compatibility with existing views
                req.session.user = payloadUser;
                logger.info('User logged in', { userId: payloadUser.id, email: payloadUser.email, ip: req.ip });
                res.redirect('/profile');
            } catch (e) {
                return res.redirect('/login?error=Invalid%20login');
            }
        });
    } catch (e) {
        return res.redirect('/login?error=Invalid%20login');
    }
});

app.post('/signup', async (req, res) => {
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

app.post('/update-bio', (req, res) => {
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
app.post('/change-password', async (req, res) => {
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
