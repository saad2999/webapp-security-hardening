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

// Winston Logger (Initialize FIRST)
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
        new winston.transports.Console()
    ]
});
app.set('logger', logger);

// Session with secure config
app.use(session({
    secret: process.env.SESSION_SECRET || 'clearway-2025-fallback-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 2 * 60 * 60 * 1000 // 2 hours
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
                } catch (e) { 
                    logger.warn('CSRF token generation failed', { error: e.message });
                }
            }
            next();
        });
    }

    return csrfProtection(req, res, (err) => {
        if (err) {
            logger.error('CSRF validation failed', { 
                error: err.message, 
                path: req.path,
                method: req.method 
            });
            return res.redirect(req.path.includes('profile') ? '/profile?error=Security%20token%20invalid' : '/?error=Security%20error');
        }
        next();
    });
});

// Rate limiting
const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200, standardHeaders: true, legacyHeaders: false });
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false });
app.use(globalLimiter);

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
        } catch (e) { 
            logger.debug('JWT verification failed', { error: e.message });
        }
    } else if (req.session?.user) {
        res.locals.user = req.session.user;
        req.user = req.session.user;
    }

    next();
});

// Database Connection – Cloud Run Compatible with Unix Socket
logger.info('🔧 Configuring database connection...');
logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
logger.info(`INSTANCE_CONNECTION_NAME: ${process.env.INSTANCE_CONNECTION_NAME || 'NOT SET'}`);

const dbConfig = {
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'Clearway_Cyber_db',
    connectTimeout: 10000,
    charset: 'utf8mb4'
};

// Use Unix socket on Cloud Run, TCP locally
if (process.env.INSTANCE_CONNECTION_NAME) {
    // Cloud Run with Unix socket
    dbConfig.socketPath = `/cloudsql/${process.env.INSTANCE_CONNECTION_NAME}`;
    logger.info(`✅ Using Cloud SQL Unix socket: ${dbConfig.socketPath}`);
} else {
    // Local development with TCP
    dbConfig.host = process.env.DB_HOST || '127.0.0.1';
    dbConfig.port = process.env.DB_PORT || 3306;
    logger.info(`✅ Using MySQL TCP connection: ${dbConfig.host}:${dbConfig.port}`);
}

let db;
let dbConnected = false;

function createDatabaseConnection() {
    db = mysql.createConnection(dbConfig);

    db.on('error', (err) => {
        logger.error('Database connection error:', { error: err.message, code: err.code });
        dbConnected = false;
        
        // Attempt to reconnect
        if (err.code === 'PROTOCOL_CONNECTION_LOST' || err.code === 'ECONNRESET') {
            logger.info('Attempting to reconnect to database...');
            setTimeout(createDatabaseConnection, 2000);
        }
    });

    db.connect(err => {
        if (err) {
            logger.error("❌ Database connection failed:", { 
                error: err.message, 
                code: err.code,
                socketPath: dbConfig.socketPath,
                host: dbConfig.host 
            });
            dbConnected = false;
        } else {
            logger.info("✅ Database connected successfully!");
            dbConnected = true;
        }
    });
}

createDatabaseConnection();

// Health check – accurate DB status
app.get('/health', (req, res) => {
    const dbStatus = dbConnected && db && db.state === 'authenticated' ? 'connected' : 'disconnected';
    res.json({ 
        status: 'ok', 
        time: Date.now(), 
        database: dbStatus,
        environment: process.env.NODE_ENV || 'development',
        socketPath: dbConfig.socketPath || 'N/A',
        host: dbConfig.host || 'N/A'
    });
});

// Safe query wrapper – fully protected with retry and try/catch
const safeQuery = (sql, params = [], callback) => {
    if (!db || !db.query) {
        logger.error("DB not initialized");
        return callback(new Error("DB not ready"), null);
    }

    if (!dbConnected) {
        logger.warn("DB not connected, attempting query anyway");
    }

    try {
        db.query(sql, params, (err, results) => {
            if (err) {
                logger.error("Query error:", { 
                    error: err.message, 
                    code: err.code, 
                    sql: sql.substring(0, 100),
                    params: params 
                });
                
                if (['ECONNRESET', 'ETIMEDOUT', 'PROTOCOL_CONNECTION_LOST'].includes(err.code)) {
                    logger.warn("Transient DB error – retrying once");
                    dbConnected = false;
                    setTimeout(() => {
                        createDatabaseConnection();
                        setTimeout(() => db.query(sql, params, callback), 1000);
                    }, 1000);
                    return;
                }
            }
            callback(err, results || []);
        });
    } catch (e) {
        logger.error("Synchronous DB error", { error: e.message, stack: e.stack });
        callback(e, null);
    }
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
app.post('/login', loginLimiter, (req, res) => {
    const { email = '', password = '' } = req.body;
    
    logger.info(`Login attempt for: ${email}`);
    
    if (!validatorLib.isEmail(String(email)) || !password) {
        logger.warn(`Invalid login format: ${email}`);
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
        const ok = await bcrypt.compare(password + PEPPER, user.password);
        if (!ok) {
            logger.warn(`FAILED_LOGIN email=${email} ip=${req.ip} reason=wrong_password`);
            return res.redirect('/login?error=Invalid%20login');
        }
        logger.info(`SUCCESSFUL_LOGIN email=${email} ip=${req.ip}`);

        const payloadUser = { id: user.id, email: user.email, name: user.name, bio: user.bio };
        const token = jwt.sign({ user: payloadUser }, JWT_SECRET, { expiresIn: '2h' });
        res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 2 * 60 * 60 * 1000 });
        req.session.user = payloadUser;
        res.redirect('/profile');
    });
});

// Signup
app.post('/signup', ids.idsMiddleware, csrfProtection, async (req, res) => {
    try {
        let { email, password, name, bio = '' } = req.body;
        
        logger.info(`Signup attempt: ${email}`);
        
        if (!email || !password) {
            logger.warn('Signup missing fields');
            return res.redirect('/signup?error=Missing%20fields');
        }
        
        if (!validatorLib.isEmail(email)) {
            logger.warn(`Invalid email format: ${email}`);
            return res.redirect('/signup?error=Invalid%20email');
        }

        const pwdCheck = validator.validatePassword(password);
        if (!pwdCheck.ok) {
            logger.warn('Weak password attempt');
            return res.redirect('/signup?error=Weak%20password');
        }

        name = validatorLib.escape(name || '');
        bio = validatorLib.escape(bio);

        const hashed = await bcrypt.hash(password + PEPPER, SALT_ROUNDS);

        safeQuery('INSERT INTO users (email, password, name, bio) VALUES (?, ?, ?, ?)', [email, hashed, name, bio], (err) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    logger.warn(`Duplicate email: ${email}`);
                    return res.redirect('/signup?error=Email%20exists');
                }
                logger.error("Signup DB error", { error: err.message, code: err.code });
                return res.redirect('/signup?error=Registration%20failed');
            }
            logger.info(`New user registered: ${email}`);
            res.redirect('/login?success=Account%20created');
        });
    } catch (e) {
        logger.error("Signup exception", { error: e.message, stack: e.stack });
        res.redirect('/signup?error=Server%20error');
    }
});

// Update Bio
app.post('/update-bio', ids.idsMiddleware, csrfProtection, (req, res) => {
    const user = res.locals.user;
    
    logger.info(`Bio update attempt`, { userId: user?.id, email: user?.email });
    
    if (!user) {
        logger.warn('Bio update attempted without authentication');
        return res.redirect('/login');
    }

    const rawBio = req.body.bio || '';
    
    logger.info(`Bio content`, { rawBio: rawBio.substring(0, 50), length: rawBio.length });
    
    const bioCheck = validator.validateBio(rawBio);
    if (!bioCheck.ok) {
        logger.warn('Invalid bio content', { reason: bioCheck.error });
        return res.redirect('/profile?error=Invalid%20bio');
    }

    logger.info(`Executing bio update query`, { 
        userId: user.id, 
        bioLength: bioCheck.sanitized.length 
    });

    safeQuery('UPDATE users SET bio = ? WHERE id = ?', [bioCheck.sanitized, user.id], (err, results) => {
        if (err) {
            logger.error("Bio update failed", { 
                error: err.message, 
                code: err.code,
                userId: user.id 
            });
            return res.redirect('/profile?error=Update%20failed');
        }

        logger.info(`Bio updated successfully`, { 
            userId: user.id, 
            affectedRows: results?.affectedRows 
        });

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

// Change Password
app.post('/change-password', ids.idsMiddleware, csrfProtection, async (req, res) => {
    const user = res.locals.user;
    
    logger.info(`Password change attempt`, { userId: user?.id });
    
    if (!user) {
        logger.warn('Password change attempted without authentication');
        return res.redirect('/login');
    }

    const newPassword = req.body.newPassword;
    const pwdCheck = validator.validatePassword(newPassword);
    if (!pwdCheck.ok) {
        logger.warn('Weak password in change attempt');
        return res.redirect('/profile?error=Weak%20password');
    }

    try {
        const hashed = await bcrypt.hash(newPassword + PEPPER, SALT_ROUNDS);
        
        safeQuery('UPDATE users SET password = ? WHERE id = ?', [hashed, user.id], (err, results) => {
            if (err) {
                logger.error("Password change failed", { error: err.message, userId: user.id });
                return res.redirect('/profile?error=Password%20change%20failed');
            }
            logger.info(`Password changed successfully`, { userId: user.id });
            res.redirect('/profile?success=Password%20changed');
        });
    } catch (e) {
        logger.error("Password hashing failed", { error: e.message });
        res.redirect('/profile?error=Server%20error');
    }
});

// API Endpoints
function requireAuthApi(req, res, next) {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    if (!token) {
        logger.warn('API request without token');
        return res.status(401).json({ error: 'Unauthorized' });
    }
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        req.user = payload.user;
        next();
    } catch (e) {
        logger.warn('API request with invalid token', { error: e.message });
        res.status(401).json({ error: 'Invalid token' });
    }
}

app.get('/api/profile', requireAuthApi, (req, res) => {
    res.json({ user: req.user });
});

app.post('/api/update-bio', requireAuthApi, (req, res) => {
    const csrfToken = req.headers['x-csrf-token'] || req.body._csrf;
    if (!csrfToken || !req.csrfToken || csrfToken !== req.csrfToken()) {
        logger.warn('API bio update with invalid CSRF');
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }

    const rawBio = req.body.bio || '';
    const bioCheck = validator.validateBio(rawBio);
    if (!bioCheck.ok) {
        logger.warn('API bio update with invalid content');
        return res.status(400).json({ error: 'Invalid bio' });
    }

    safeQuery('UPDATE users SET bio = ? WHERE id = ?', [bioCheck.sanitized, req.user.id], (err, results) => {
        if (err) {
            logger.error('API bio update failed', { error: err.message });
            return res.status(500).json({ error: 'Update failed' });
        }
        
        const updatedUser = { ...req.user, bio: bioCheck.sanitized };
        const newToken = jwt.sign({ user: updatedUser }, JWT_SECRET, { expiresIn: '2h' });
        res.json({ success: true, user: updatedUser, token: newToken });
    });
});

// Global error handler – prevents Cloud Run 503 crashes
app.use((err, req, res, next) => {
    logger.error("Unhandled error", { 
        error: err.message, 
        stack: err.stack,
        path: req.path,
        method: req.method 
    });
    
    if (res.headersSent) return next(err);
    
    // Don't redirect for API endpoints
    if (req.path.startsWith('/api/')) {
        return res.status(500).json({ error: 'Internal server error' });
    }
    
    res.redirect('/?error=Service%20temporarily%20unavailable');
});

// Start server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    logger.info('═══════════════════════════════════════════════════════════');
    logger.info('🚀 CLEARWAY CYBER - WEEK 5 COMPLETE: SQLi & CSRF PROTECTED');
    logger.info('═══════════════════════════════════════════════════════════');
    logger.info(`📍 Server running on port: ${PORT}`);
    logger.info(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    logger.info(`🔌 Connection: ${process.env.INSTANCE_CONNECTION_NAME ? 'Cloud SQL (Unix socket)' : 'Local MySQL (TCP)'}`);
    logger.info(`🗄️  Database: ${dbConfig.database}`);
    logger.info(`🔒 CSRF tokens required on all state-changing requests`);
    logger.info('✅ Ready for Burp Suite testing and ethical hacking report');
    logger.info('═══════════════════════════════════════════════════════════');
});