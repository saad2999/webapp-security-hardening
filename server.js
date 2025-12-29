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
const winston = require('winston');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const validator = require('./validator');
const validatorLib = require('validator');
const ids = require('./ids');
const cors = require('cors');
const csrf = require('@dr.pogodin/csurf');
const rateLimiter = require('./rateLimiter'); // Our custom rate limiter

const app = express();

// Trust proxy for Cloud Run
app.set('trust proxy', true);

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
    transports: [new winston.transports.Console()]
});
app.set('logger', logger);

// Layouts and views
app.use(expressLayout);
app.set('layout', 'layout');
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(morgan('dev'));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static('public'));

// Session
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

app.use(cookieParser());

// CORS
app.use(cors({
    origin: process.env.ALLOWED_ORIGIN || 'http://localhost:3000',
    credentials: true,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}));

// Helmet
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
        httpOnly: false,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
    }
});

// Secrets
const PEPPER = process.env.PEPPER || 'ClearwayCyberHardenedPepper2025DoNotShare!@#';
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-jwt-secret-2025-change-in-production';
const SALT_ROUNDS = 12;

// Rate Limiting using our custom limiter
app.use(rateLimiter.middleware({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 200, // 200 requests per window
    skip: (req) => req.path === '/health' // Skip health checks
}));

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
        } catch (e) {
            logger.debug('JWT verification failed', { error: e.message });
        }
    } else if (req.session?.user) {
        res.locals.user = req.session.user;
        req.user = req.session.user;
    }

    next();
});

// Database Connection
const dbConfig = {
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'Clearway_Cyber_db',
    connectTimeout: 10000,
    charset: 'utf8mb4'
};

if (process.env.INSTANCE_CONNECTION_NAME) {
    dbConfig.socketPath = `/cloudsql/${process.env.INSTANCE_CONNECTION_NAME}`;
} else {
    dbConfig.host = process.env.DB_HOST || '127.0.0.1';
    dbConfig.port = process.env.DB_PORT || 3306;
}

const db = mysql.createConnection(dbConfig);
let dbConnected = false;

db.connect(err => {
    if (err) {
        logger.error("❌ Database connection failed:", { error: err.message });
        dbConnected = false;
    } else {
        logger.info("✅ Database connected successfully!");
        dbConnected = true;
    }
});

// Handle database errors
db.on('error', (err) => {
    logger.error('Database connection error:', { error: err.message });
    dbConnected = false;
    
    if (err.code === 'PROTOCOL_CONNECTION_LOST' || err.code === 'ECONNRESET') {
        logger.info('Attempting to reconnect to database...');
        setTimeout(() => {
            db.connect(err => {
                if (err) {
                    logger.error("Reconnection failed:", { error: err.message });
                } else {
                    logger.info("Reconnected to database!");
                    dbConnected = true;
                }
            });
        }, 2000);
    }
});

// Safe query wrapper
const safeQuery = (sql, params = [], callback) => {
    if (!dbConnected) {
        logger.warn("DB not connected, attempting query anyway");
    }

    db.query(sql, params, (err, results) => {
        if (err) {
            logger.error("Query error:", {
                error: err.message,
                code: err.code,
                sql: sql.substring(0, 100)
            });
        }
        callback(err, results || []);
    });
};

// Routes
app.get('/', (req, res) => res.render('index'));
app.get('/login', (req, res) => res.render('login'));
app.get('/signup', (req, res) => res.render('signup'));

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    req.session.destroy(() => {});
    res.redirect('/');
});

// Profile route
app.get('/profile', (req, res) => {
    if (!res.locals.user) {
        return res.redirect('/login');
    }

    csrfProtection(req, res, (err) => {
        if (err) {
            logger.error('CSRF error during profile load', { error: err.message });
            return res.redirect('/?error=Security%20token%20error');
        }

        try {
            const token = req.csrfToken();
            res.render('profile', {
                csrfToken: token
            });
        } catch (e) {
            logger.error('Error generating CSRF token', { error: e.message });
            return res.redirect('/?error=Security%20error');
        }
    });
});

// Login route with stricter rate limiting
app.post('/login', rateLimiter.middleware({
    windowMs: 15 * 60 * 1000,
    max: 10,
    keyGenerator: (req) => {
        const email = req.body.email || 'unknown';
        return `${req.ip}:login:${email}`;
    }
}), (req, res) => {
    const { email = '', password = '' } = req.body;

    if (!validatorLib.isEmail(String(email)) || !password) {
        return res.redirect('/login?error=Invalid%20login');
    }

    safeQuery('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) {
            logger.error(`Database error during login for ${email}:`, { error: err.message });
            return res.redirect('/login?error=Service%20unavailable');
        }

        if (results.length === 0) {
            logger.warn(`FAILED_LOGIN email=${email} ip=${req.ip}`);
            return res.redirect('/login?error=Invalid%20login');
        }

        const user = results[0];
        try {
            const ok = await bcrypt.compare(password + PEPPER, user.password);
            if (!ok) {
                logger.warn(`FAILED_LOGIN email=${email} ip=${req.ip} reason=wrong_password`);
                return res.redirect('/login?error=Invalid%20login');
            }

            const payloadUser = { id: user.id, email: user.email, name: user.name, bio: user.bio };
            const token = jwt.sign({ user: payloadUser }, JWT_SECRET, { expiresIn: '2h' });
            res.cookie('token', token, {
                httpOnly: true,
                sameSite: 'lax',
                secure: process.env.NODE_ENV === 'production',
                maxAge: 2 * 60 * 60 * 1000
            });
            req.session.user = payloadUser;
            res.redirect('/profile');
        } catch (bcryptErr) {
            logger.error('Bcrypt error', { error: bcryptErr.message });
            return res.redirect('/login?error=Service%20error');
        }
    });
});

// Signup route
app.post('/signup', csrfProtection, ids.idsMiddleware, async (req, res) => {
    try {
        let { email, password, name, bio = '' } = req.body;

        if (!email || !password) {
            return res.redirect('/signup?error=Missing%20fields');
        }

        if (!validatorLib.isEmail(email)) {
            return res.redirect('/signup?error=Invalid%20email');
        }

        const pwdCheck = validator.validatePassword(password);
        if (!pwdCheck.ok) {
            return res.redirect('/signup?error=Weak%20password');
        }

        name = validatorLib.escape(name || '');
        bio = validatorLib.escape(bio);

        const hashed = await bcrypt.hash(password + PEPPER, SALT_ROUNDS);

        safeQuery('INSERT INTO users (email, password, name, bio) VALUES (?, ?, ?, ?)', 
            [email, hashed, name, bio], (err) => {
                if (err) {
                    if (err.code === 'ER_DUP_ENTRY') {
                        return res.redirect('/signup?error=Email%20exists');
                    }
                    logger.error("Signup DB error", { error: err.message });
                    return res.redirect('/signup?error=Registration%20failed');
                }
                res.redirect('/login?success=Account%20created');
            });
    } catch (e) {
        logger.error("Signup exception", { error: e.message });
        res.redirect('/signup?error=Server%20error');
    }
});

// Update Bio route
app.post('/update-bio', csrfProtection, ids.idsMiddleware, (req, res) => {
    const user = res.locals.user;

    if (!user) {
        return res.redirect('/login');
    }

    const rawBio = req.body.bio || '';
    const bioCheck = validator.validateBio(rawBio);
    if (!bioCheck.ok) {
        return res.redirect('/profile?error=Invalid%20bio');
    }

    safeQuery('UPDATE users SET bio = ? WHERE id = ?', [bioCheck.sanitized, user.id], (err, results) => {
        if (err) {
            logger.error("Bio update DB failed", { error: err.message });
            return res.redirect('/profile?error=Update%20failed');
        }

        const updatedUser = { ...user, bio: bioCheck.sanitized };
        req.session.user = updatedUser;

        try {
            const token = jwt.sign({ user: updatedUser }, JWT_SECRET, { expiresIn: '2h' });
            res.cookie('token', token, {
                httpOnly: true,
                sameSite: 'lax',
                secure: process.env.NODE_ENV === 'production',
                maxAge: 2 * 60 * 60 * 1000
            });
        } catch (e) {
            logger.error('JWT signing failed', { error: e.message });
        }

        res.redirect('/profile?success=Bio%20updated');
    });
});

// Change Password route
app.post('/change-password', csrfProtection, ids.idsMiddleware, async (req, res) => {
    const user = res.locals.user;

    if (!user) {
        return res.redirect('/login');
    }

    const newPassword = req.body.newPassword;

    if (!newPassword) {
        return res.redirect('/profile?error=Password%20required');
    }

    const pwdCheck = validator.validatePassword(newPassword);
    if (!pwdCheck.ok) {
        return res.redirect('/profile?error=Weak%20password');
    }

    try {
        const hashed = await bcrypt.hash(newPassword + PEPPER, SALT_ROUNDS);

        safeQuery('UPDATE users SET password = ? WHERE id = ?', [hashed, user.id], (err, results) => {
            if (err) {
                logger.error("Password change DB failed", { error: err.message });
                return res.redirect('/profile?error=Password%20change%20failed');
            }
            res.redirect('/profile?success=Password%20changed');
        });
    } catch (e) {
        logger.error("Password hashing failed", { error: e.message });
        res.redirect('/profile?error=Server%20error');
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        time: Date.now(),
        database: dbConnected ? 'connected' : 'disconnected',
        environment: process.env.NODE_ENV || 'development'
    });
});

// Global error handler
app.use((err, req, res, next) => {
    logger.error("Unhandled error", {
        error: err.message,
        path: req.path,
        method: req.method
    });

    if (err.code === 'EBADCSRFTOKEN') {
        logger.error('CSRF token validation failed', { path: req.path });
        return res.redirect('/profile?error=Security%20token%20expired.%20Please%20refresh');
    }

    res.redirect('/?error=Service%20temporarily%20unavailable');
});

// Start server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    logger.info('═══════════════════════════════════════════════════════════');
    logger.info('🚀 CLEARWAY CYBER - WEEK 5: SQLi & CSRF PROTECTED');
    logger.info('═══════════════════════════════════════════════════════════');
    logger.info(`📍 Server running on port: ${PORT}`);
    logger.info(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    logger.info(`📊 Custom rate limiting enabled (no express-rate-limit)`);
    logger.info(`🔒 CSRF protection enabled`);
    logger.info('✅ Ready for testing');
    logger.info('═══════════════════════════════════════════════════════════');
});