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

app.set('trust proxy', true);

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    defaultMeta: { service: 'clearway-cyber' },
    transports: [new winston.transports.Console({ format: winston.format.simple() })]
});

// ======================
// MIDDLEWARE SETUP
// ======================
app.use(expressLayout);
app.set('layout', 'layout');
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: [],
        },
    },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }
}));

app.use(morgan('combined', { stream: { write: (msg) => logger.info(msg.trim()) } }));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(cookieParser());

app.use(session({
    secret: process.env.SESSION_SECRET || 'clearway-2025-fallback-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 2 * 60 * 60 * 1000
    }
}));

const csrfProtection = csrf({
    cookie: {
        httpOnly: true, 
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
    }
});

app.use(cors({
    origin: process.env.ALLOWED_ORIGIN || 'http://localhost:3000',
    credentials: true
}));

// ======================
// DATABASE CONFIG
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

// Health Check
app.get('/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({ status: 'healthy' });
    } catch (e) { res.status(503).json({ status: 'unhealthy' }); }
});

// Auth Middleware
app.use((req, res, next) => {
    const token = req.cookies?.token;
    if (token) {
        try {
            const payload = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret');
            req.user = payload.user;
            res.locals.user = payload.user;
        } catch (e) { logger.debug('JWT error'); }
    }
    next();
});

// ======================
// ROUTES
// ======================
app.get('/', (req, res) => res.render('index'));
app.get('/login', (req, res) => res.render('login'));
app.get('/signup', csrfProtection, (req, res) => res.render('signup', { csrfToken: req.csrfToken() }));

app.get('/profile', csrfProtection, (req, res) => {
    if (!req.user) return res.redirect('/login');
    res.render('profile', { user: req.user, csrfToken: req.csrfToken() });
});

// NEW LOGOUT ROUTE
app.get('/logout', (req, res) => {
    res.clearCookie('token');
    if (req.session) {
        req.session.destroy(() => {
            res.redirect('/login?success=Logged out');
        });
    } else {
        res.redirect('/login');
    }
});

app.post('/update-bio', csrfProtection, ids.idsMiddleware, async (req, res) => {
    if (!req.user) return res.redirect('/login');
    const bioCheck = validator.validateBio(req.body.bio || '');
    if (!bioCheck.ok) return res.redirect('/profile?error=Invalid');

    try {
        await pool.execute('UPDATE users SET bio = ? WHERE id = ?', [bioCheck.sanitized, req.user.id]);
        const updatedUser = { ...req.user, bio: bioCheck.sanitized };
        const token = jwt.sign({ user: updatedUser }, process.env.JWT_SECRET || 'fallback-secret', { expiresIn: '2h' });
        res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax' });
        res.redirect('/profile?success=Updated');
    } catch (e) { res.redirect('/profile?error=Failed'); }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
    logger.info(`🚀 Server running on port ${PORT}`);
});