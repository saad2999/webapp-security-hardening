require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise'); // Using promise-based version for async/await
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
// 1. CRITICAL CLOUD RUN FIXES
// ======================

// Trust proxy for Cloud Run
app.set('trust proxy', true);

// Winston Logger with Cloud Run structured logging
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json() // Use JSON for Cloud Logging
    ),
    defaultMeta: { service: 'clearway-cyber' },
    transports: [
        new winston.transports.Console({
            format: winston.format.simple()
        })
    ]
});

// IMPORTANT: Add startup logging
logger.info('🚀 Starting Clearway Cyber application on Cloud Run');
logger.info('📦 Environment:', { NODE_ENV: process.env.NODE_ENV, PORT: process.env.PORT });

// Graceful shutdown handling for Cloud Run
process.on('SIGTERM', () => {
    logger.info('SIGTERM received, shutting down gracefully');
    if (global.dbConnection) {
        global.dbConnection.end();
    }
    process.exit(0);
});

process.on('uncaughtException', (error) => {
    logger.error('💥 UNCAUGHT EXCEPTION:', error);
    // Don't exit in production - let Cloud Run restart
    if (process.env.NODE_ENV !== 'production') {
        process.exit(1);
    }
});

process.on('unhandledRejection', (reason, promise) => {
    logger.error('💥 UNHANDLED REJECTION at:', promise, 'reason:', reason);
});

// ======================
// 2. MIDDLEWARE SETUP
// ======================

app.use(expressLayout);
app.set('layout', 'layout');
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Logging middleware
app.use(morgan('combined', {
    stream: {
        write: (message) => logger.info(message.trim())
    }
}));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static('public'));

// Session configuration for production
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

// CORS configuration
app.use(cors({
    origin: process.env.ALLOWED_ORIGIN || 'http://localhost:3000',
    credentials: true,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}));

// Security headers
app.use(helmet({
    contentSecurityPolicy: false, // Disable for now to simplify
    crossOriginEmbedderPolicy: false
}));

// CSRF Protection
const csrfProtection = csrf({
    cookie: {
        httpOnly: false,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
    }
});

// ======================
// 3. DATABASE CONFIGURATION
// ======================

logger.info('🔧 Configuring database connection...');
logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
logger.info(`INSTANCE_CONNECTION_NAME: ${process.env.INSTANCE_CONNECTION_NAME || 'NOT SET'}`);

const dbConfig = {
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'Clearway_Cyber_db',
    connectTimeout: 10000,
    charset: 'utf8mb4',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

// Use Unix socket on Cloud Run, TCP locally
if (process.env.INSTANCE_CONNECTION_NAME) {
    dbConfig.socketPath = `/cloudsql/${process.env.INSTANCE_CONNECTION_NAME}`;
    logger.info(`✅ Using Cloud SQL Unix socket: ${dbConfig.socketPath}`);
} else {
    dbConfig.host = process.env.DB_HOST || '127.0.0.1';
    dbConfig.port = process.env.DB_PORT || 3306;
    logger.info(`✅ Using MySQL TCP connection: ${dbConfig.host}:${dbConfig.port}`);
}

// Create connection pool
const pool = mysql.createPool(dbConfig);

// Test database connection on startup
async function testDatabaseConnection() {
    try {
        const connection = await pool.getConnection();
        logger.info('✅ Database connected successfully!');
        connection.release();
        return true;
    } catch (err) {
        logger.error('❌ Database connection failed:', {
            error: err.message,
            code: err.code,
            socketPath: dbConfig.socketPath,
            host: dbConfig.host
        });
        // Don't exit - let the app start and try to reconnect
        return false;
    }
}

// Global connection for cleanup
global.dbConnection = pool;

// ======================
// 4. RATE LIMITER (Simple in-memory)
// ======================

class SimpleRateLimiter {
    constructor(windowMs, max) {
        this.windowMs = windowMs;
        this.max = max;
        this.hits = new Map();
    }

    middleware() {
        return (req, res, next) => {
            if (req.path === '/health') return next();
            
            const key = this.getKey(req);
            const now = Date.now();
            const windowStart = now - this.windowMs;
            
            if (!this.hits.has(key)) this.hits.set(key, []);
            
            const hitsInWindow = this.hits.get(key).filter(time => time > windowStart);
            
            if (hitsInWindow.length >= this.max) {
                logger.warn(`Rate limit exceeded for ${key}`);
                return res.status(429).json({ error: 'Too many requests' });
            }
            
            hitsInWindow.push(now);
            this.hits.set(key, hitsInWindow);
            
            // Clean up old entries occasionally
            if (Math.random() < 0.01) this.cleanup();
            
            next();
        };
    }

    getKey(req) {
        if (req.path === '/login' && req.method === 'POST') {
            const email = req.body.email || 'unknown';
            return `login:${req.ip}:${email}`;
        }
        return req.ip;
    }

    cleanup() {
        const now = Date.now();
        const windowStart = now - this.windowMs;
        for (const [key, hits] of this.hits.entries()) {
            const recentHits = hits.filter(time => time > windowStart);
            if (recentHits.length === 0) this.hits.delete(key);
            else this.hits.set(key, recentHits);
        }
    }
}

const globalLimiter = new SimpleRateLimiter(15 * 60 * 1000, 200);
const loginLimiter = new SimpleRateLimiter(15 * 60 * 1000, 10);

// Apply rate limiting
app.use(globalLimiter.middleware());

// ======================
// 5. AUTHENTICATION MIDDLEWARE
// ======================

app.use((req, res, next) => {
    res.locals.error = req.query.error;
    res.locals.success = req.query.success;
    res.locals.user = null;

    const token = req.cookies?.token || req.headers.authorization?.split(' ')[1];
    if (token) {
        try {
            const payload = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret');
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

// ======================
// 6. ROUTES
// ======================

// Health check endpoint (CRITICAL for Cloud Run)
app.get('/health', async (req, res) => {
    try {
        const dbStatus = await testDatabaseConnection();
        res.json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            database: dbStatus ? 'connected' : 'disconnected',
            environment: process.env.NODE_ENV || 'development',
            service: 'clearway-cyber',
            uptime: process.uptime()
        });
    } catch (error) {
        logger.error('Health check failed:', error);
        res.status(503).json({
            status: 'unhealthy',
            error: error.message
        });
    }
});

// Root endpoint
app.get('/', (req, res) => {
    logger.info('Home page accessed', { ip: req.ip });
    res.render('index');
});

app.get('/login', (req, res) => res.render('login'));
app.get('/signup', (req, res) => res.render('signup'));

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    req.session.destroy(() => {});
    res.redirect('/');
});

// Profile endpoint
app.get('/profile', csrfProtection, (req, res) => {
    if (!res.locals.user) {
        logger.warn('Unauthenticated access to profile');
        return res.redirect('/login');
    }
    
    try {
        const token = req.csrfToken();
        res.render('profile', { csrfToken: token });
    } catch (error) {
        logger.error('CSRF token generation failed:', error);
        res.redirect('/?error=Security error');
    }
});

// Login route with rate limiting
app.post('/login', loginLimiter.middleware(), async (req, res) => {
    const { email = '', password = '' } = req.body;
    logger.info('Login attempt', { email: email.substring(0, 3) + '***', ip: req.ip });

    if (!validatorLib.isEmail(String(email)) || !password) {
        return res.redirect('/login?error=Invalid login');
    }

    try {
        const [results] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        
        if (results.length === 0) {
            logger.warn('Login failed: user not found', { email: email.substring(0, 3) + '***' });
            return res.redirect('/login?error=Invalid login');
        }

        const user = results[0];
        const pepper = process.env.PEPPER || 'ClearwayCyberHardenedPepper2025';
        const ok = await bcrypt.compare(password + pepper, user.password);
        
        if (!ok) {
            logger.warn('Login failed: wrong password', { email: email.substring(0, 3) + '***' });
            return res.redirect('/login?error=Invalid login');
        }

        logger.info('Login successful', { userId: user.id, email: email.substring(0, 3) + '***' });
        
        const payloadUser = { 
            id: user.id, 
            email: user.email, 
            name: user.name, 
            bio: user.bio 
        };
        
        const token = jwt.sign(
            { user: payloadUser }, 
            process.env.JWT_SECRET || 'fallback-secret',
            { expiresIn: '2h' }
        );
        
        res.cookie('token', token, {
            httpOnly: true,
            sameSite: 'lax',
            secure: process.env.NODE_ENV === 'production',
            maxAge: 2 * 60 * 60 * 1000
        });
        
        req.session.user = payloadUser;
        res.redirect('/profile');
        
    } catch (error) {
        logger.error('Login error:', error);
        res.redirect('/login?error=Service error');
    }
});

// Signup route
app.post('/signup', csrfProtection, ids.idsMiddleware, async (req, res) => {
    try {
        let { email, password, name, bio = '' } = req.body;
        logger.info('Signup attempt', { email: email.substring(0, 3) + '***', ip: req.ip });

        if (!email || !password) {
            return res.redirect('/signup?error=Missing fields');
        }

        if (!validatorLib.isEmail(email)) {
            return res.redirect('/signup?error=Invalid email');
        }

        const pwdCheck = validator.validatePassword(password);
        if (!pwdCheck.ok) {
            return res.redirect('/signup?error=Weak password');
        }

        name = validatorLib.escape(name || '');
        bio = validatorLib.escape(bio);

        const pepper = process.env.PEPPER || 'ClearwayCyberHardenedPepper2025';
        const hashed = await bcrypt.hash(password + pepper, 12);

        await pool.execute(
            'INSERT INTO users (email, password, name, bio) VALUES (?, ?, ?, ?)',
            [email, hashed, name, bio]
        );

        logger.info('New user registered', { email: email.substring(0, 3) + '***' });
        res.redirect('/login?success=Account created');
        
    } catch (error) {
        logger.error('Signup error:', error);
        
        if (error.code === 'ER_DUP_ENTRY') {
            res.redirect('/signup?error=Email exists');
        } else {
            res.redirect('/signup?error=Registration failed');
        }
    }
});

// Update bio route
app.post('/update-bio', csrfProtection, ids.idsMiddleware, async (req, res) => {
    const user = res.locals.user;
    
    if (!user) {
        return res.redirect('/login');
    }

    const rawBio = req.body.bio || '';
    const bioCheck = validator.validateBio(rawBio);
    
    if (!bioCheck.ok) {
        return res.redirect('/profile?error=Invalid bio');
    }

    try {
        await pool.execute('UPDATE users SET bio = ? WHERE id = ?', [bioCheck.sanitized, user.id]);
        
        const updatedUser = { ...user, bio: bioCheck.sanitized };
        req.session.user = updatedUser;
        
        const token = jwt.sign(
            { user: updatedUser }, 
            process.env.JWT_SECRET || 'fallback-secret',
            { expiresIn: '2h' }
        );
        
        res.cookie('token', token, {
            httpOnly: true,
            sameSite: 'lax',
            secure: process.env.NODE_ENV === 'production',
            maxAge: 2 * 60 * 60 * 1000
        });
        
        res.redirect('/profile?success=Bio updated');
        
    } catch (error) {
        logger.error('Bio update error:', error);
        res.redirect('/profile?error=Update failed');
    }
});

// Change password route
app.post('/change-password', csrfProtection, ids.idsMiddleware, async (req, res) => {
    const user = res.locals.user;
    
    if (!user) {
        return res.redirect('/login');
    }

    const newPassword = req.body.newPassword;
    
    if (!newPassword) {
        return res.redirect('/profile?error=Password required');
    }

    const pwdCheck = validator.validatePassword(newPassword);
    if (!pwdCheck.ok) {
        return res.redirect('/profile?error=Weak password');
    }

    try {
        const pepper = process.env.PEPPER || 'ClearwayCyberHardenedPepper2025';
        const hashed = await bcrypt.hash(newPassword + pepper, 12);
        
        await pool.execute('UPDATE users SET password = ? WHERE id = ?', [hashed, user.id]);
        res.redirect('/profile?success=Password changed');
        
    } catch (error) {
        logger.error('Password change error:', error);
        res.redirect('/profile?error=Password change failed');
    }
});

// API endpoints
function requireAuthApi(req, res, next) {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret');
        req.user = payload.user;
        next();
    } catch (e) {
        res.status(401).json({ error: 'Invalid token' });
    }
}

app.get('/api/profile', requireAuthApi, (req, res) => {
    res.json({ user: req.user });
});

app.post('/api/update-bio', requireAuthApi, csrfProtection, async (req, res) => {
    const rawBio = req.body.bio || '';
    const bioCheck = validator.validateBio(rawBio);
    
    if (!bioCheck.ok) {
        return res.status(400).json({ error: 'Invalid bio' });
    }

    try {
        await pool.execute('UPDATE users SET bio = ? WHERE id = ?', [bioCheck.sanitized, req.user.id]);
        
        const updatedUser = { ...req.user, bio: bioCheck.sanitized };
        const newToken = jwt.sign(
            { user: updatedUser }, 
            process.env.JWT_SECRET || 'fallback-secret',
            { expiresIn: '2h' }
        );
        
        res.json({ success: true, user: updatedUser, token: newToken });
        
    } catch (error) {
        logger.error('API bio update error:', error);
        res.status(500).json({ error: 'Update failed' });
    }
});

// 404 handler
app.use((req, res) => {
    logger.warn('404 Not Found', { path: req.path, method: req.method });
    res.status(404).render('404');
});

// Global error handler
app.use((err, req, res, next) => {
    logger.error('Application error:', {
        error: err.message,
        stack: err.stack,
        path: req.path,
        method: req.method,
        code: err.code
    });

    if (err.code === 'EBADCSRFTOKEN') {
        if (req.path.startsWith('/api/')) {
            return res.status(403).json({ error: 'Invalid CSRF token' });
        }
        return res.redirect('/profile?error=Security token expired. Please refresh');
    }

    if (req.path.startsWith('/api/')) {
        return res.status(500).json({ error: 'Internal server error' });
    }

    res.redirect('/?error=Service temporarily unavailable');
});

// ======================
// 7. SERVER STARTUP
// ======================

// CRITICAL: Use PORT environment variable from Cloud Run
const PORT = process.env.PORT || 8080;

// Start the server
app.listen(PORT, '0.0.0.0', async () => {
    logger.info('═══════════════════════════════════════════════════════════');
    logger.info('🚀 CLEARWAY CYBER - WEEK 5: SQLi & CSRF PROTECTED');
    logger.info('═══════════════════════════════════════════════════════════');
    logger.info(`📍 Server running on port: ${PORT}`);
    logger.info(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    logger.info(`🔌 Cloud Run: ${!!process.env.K_SERVICE}`);
    logger.info(`🔧 Trust proxy: ${app.get('trust proxy')}`);
    logger.info('✅ Ready for testing');
    logger.info('═══════════════════════════════════════════════════════════');
    
    // Test database connection on startup
    await testDatabaseConnection();
});

// Export for testing
module.exports = app;