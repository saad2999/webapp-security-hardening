require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise');
const path = require('path');
const morgan = require('morgan');
const expressLayout = require('express-ejs-layouts');
const cookieParser = require('cookie-parser');
const helmet = require('helmet'); // Declared once at the top
const winston = require('winston');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const validator = require('./validator');
const validatorLib = require('validator');
const ids = require('./ids');
const cors = require('cors');
const csrf = require('@dr.pogodin/csurf');
const crypto = require('crypto');

const app = express();

// ======================
// 1. CLOUD RUN CONFIGURATION
// ======================
app.set('trust proxy', true);

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    transports: [new winston.transports.Console({ format: winston.format.simple() })]
});

// ======================
// 2. MIDDLEWARE SETUP
// ======================
app.use(expressLayout);
app.set('layout', 'layout');
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(morgan('combined', { stream: { write: (msg) => logger.info(msg.trim()) }, skip: (req) => req.path === '/health' }));
app.use(bodyParser.urlencoded({ extended: false, limit: '1mb' }));
app.use(bodyParser.json({ limit: '1mb' }));
app.use(express.static('public'));
app.use(cookieParser());

app.use(session({
    name: 'clearway_session',
    secret: process.env.SESSION_SECRET || 'fallback-secret-for-dev-only',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 2 * 60 * 60 * 1000
    }
}));

app.use(cors({
    origin: process.env.ALLOWED_ORIGIN || 'http://localhost:3000',
    credentials: true
}));

// FIXED: Removed the duplicate 'const helmet' declaration that was crashing the app
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https:"],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: []
        }
    },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }
}));

// ======================
// 3. CSRF PROTECTION
// ======================
const csrfProtection = csrf({
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
    }
});

// ======================
// 4. DATABASE & AUTH
// ======================
const dbConfig = {
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'Clearway_Cyber_db',
    waitForConnections: true,
    connectionLimit: 10
};

if (process.env.INSTANCE_CONNECTION_NAME) {
    dbConfig.socketPath = `/cloudsql/${process.env.INSTANCE_CONNECTION_NAME}`;
} else {
    dbConfig.host = process.env.DB_HOST || '127.0.0.1';
    dbConfig.port = process.env.DB_PORT || 3306;
}

const pool = mysql.createPool(dbConfig);

app.use((req, res, next) => {
    res.locals.error = req.query.error;
    res.locals.success = req.query.success;
    const token = req.cookies?.token;
    if (token) {
        try {
            const payload = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret');
            req.user = payload.user;
            res.locals.user = payload.user;
        } catch (e) { res.clearCookie('token'); }
    }
    next();
});

// ======================
// 5. ROUTES
// ======================
app.get('/health', async (req, res) => {
    try { await pool.query('SELECT 1'); res.json({ status: 'healthy' }); }
    catch (e) { res.status(503).json({ status: 'unhealthy' }); }
});

app.get('/', (req, res) => res.render('index'));
app.get('/login', csrfProtection, (req, res) => res.render('login', { csrfToken: req.csrfToken() }));
app.get('/signup', csrfProtection, (req, res) => res.render('signup', { csrfToken: req.csrfToken() }));
app.get('/profile', csrfProtection, (req, res) => {
    if (!req.user) return res.redirect('/login');
    res.render('profile', { user: req.user, csrfToken: req.csrfToken() });
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    req.session.destroy(() => res.redirect('/login?success=Logged+out'));
});

app.post('/login', csrfProtection, async (req, res) => {
    const { email, password } = req.body;
    try {
        const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) return res.redirect('/login?error=Invalid');
        
        const pepper = process.env.PEPPER || 'ClearwayCyberHardenedPepper2025';
        const valid = await bcrypt.compare(password + pepper, rows[0].password);
        if (!valid) return res.redirect('/login?error=Invalid');

        const token = jwt.sign({ user: { id: rows[0].id, email: rows[0].email, name: rows[0].name, bio: rows[0].bio } }, 
            process.env.JWT_SECRET || 'fallback-secret', { expiresIn: '2h' });
        
        res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax' });
        res.redirect('/profile');
    } catch (e) { res.redirect('/login?error=Error'); }
});

app.post('/update-bio', csrfProtection, ids.idsMiddleware, async (req, res) => {
    if (!req.user) return res.redirect('/login');
    const bio = validatorLib.escape(req.body.bio || '').substring(0, 500);
    try {
        await pool.execute('UPDATE users SET bio = ? WHERE id = ?', [bio, req.user.id]);
        res.redirect('/profile?success=Updated');
    } catch (e) { res.redirect('/profile?error=Failed'); }
});

// Global Error Handler (Handles CSRF errors)
app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).redirect('/?error=Invalid+Security+Token');
    }
    logger.error(err);
    res.status(500).send('Internal Server Error');
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
    logger.info(`🚀 Server running on port: ${PORT}`);
});