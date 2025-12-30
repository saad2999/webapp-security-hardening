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
const crypto = require('crypto');

const app = express();

// ======================
// 1. CLOUD RUN CONFIGURATION
// ======================

app.set('trust proxy', true);

// Enhanced Winston Logger
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    defaultMeta: { service: 'clearway-cyber' },
    transports: [
        new winston.transports.Console({
            format: winston.format.simple()
        })
    ]
});

logger.info('🚀 Starting Clearway Cyber application on Cloud Run');

// Graceful shutdown
process.on('SIGTERM', () => {
    logger.info('SIGTERM received, shutting down gracefully');
    if (global.dbConnection) {
        global.dbConnection.end();
    }
    process.exit(0);
});

process.on('uncaughtException', (error) => {
    logger.error('💥 UNCAUGHT EXCEPTION:', error);
    if (process.env.NODE_ENV !== 'production') {
        process.exit(1);
    }
});

process.on('unhandledRejection', (reason, promise) => {
    logger.error('💥 UNHANDLED REJECTION at:', promise, 'reason:', reason);
});

// ======================
// 2. ENHANCED MIDDLEWARE SETUP
// ======================

app.use(expressLayout);
app.set('layout', 'layout');
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Enhanced logging
app.use(morgan('combined', {
    stream: {
        write: (message) => logger.info(message.trim())
    },
    skip: (req) => req.path === '/health' // Skip health checks
}));

app.use(bodyParser.urlencoded({ 
    extended: false,
    limit: '1mb' // Limit request size
}));
app.use(bodyParser.json({ limit: '1mb' }));
app.use(express.static('public'));

// Enhanced session configuration
app.use(session({
    name: 'clearway_session',
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict', // Changed from 'lax'
        maxAge: 2 * 60 * 60 * 1000,
        path: '/'
    },
    rolling: true, // Renew session on activity
    store: process.env.NODE_ENV === 'production' ? undefined : null // In production, consider Redis
}));

app.use(cookieParser());

// Enhanced CORS
app.use(cors({
    origin: process.env.ALLOWED_ORIGIN || 'http://localhost:3000',
    credentials: true,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With'],
    exposedHeaders: ['X-CSRF-Token']
}));

// Enhanced security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https:"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'", "https:"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
            frameAncestors: ["'none'"],
            formAction: ["'self'"], // Restrict form submissions
            upgradeInsecureRequests: []
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    xFrameOptions: { action: 'deny' },
    xContentTypeOptions: true,
    xXssProtection: { reportUri: '/report-xss' }
}));

// ======================
// 3. ENHANCED CSRF PROTECTION
// ======================

const csrfProtection = csrf({
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        key: '_csrf'
    },
    ignoreMethods: ['GET', 'HEAD', 'OPTIONS'],
    value: (req) => {
        // Accept token from multiple sources but validate strictly
        return req.body._csrf || req.headers['x-csrf-token'] || req.query._csrf;
    }
});

// CSRF token rotation and validation middleware
app.use((req, res, next) => {
    // Generate new CSRF token for each GET request to forms
    if (req.method === 'GET' && (req.path === '/profile' || req.path === '/login' || req.path === '/signup')) {
        req.session.csrfSecret = crypto.randomBytes(32).toString('hex');
    }
    
    // Validate CSRF token on state-changing requests
    if (req.method === 'POST' || req.method === 'PUT' || req.method === 'DELETE') {
        const csrfErrorHandler = (err) => {
            if (err.code === 'EBADCSRFTOKEN') {
                logger.warn('CSRF token validation failed', {
                    ip: req.ip,
                    path: req.path,
                    userAgent: req.get('User-Agent')
                });
                
                if (req.xhr || req.path.startsWith('/api/')) {
                    return res.status(403).json({ 
                        error: 'Invalid security token',
                        code: 'CSRF_TOKEN_INVALID'
                    });
                }
                
                // Clear invalid token and redirect
                res.clearCookie('_csrf');
                return res.redirect('/?error=Security+token+expired+or+invalid');
            }
            next(err);
        };
        
        // Apply CSRF protection with error handling
        csrfProtection(req, res, csrfErrorHandler);
    } else {
        next();
    }
});

// ======================
// 4. DATABASE CONFIGURATION
// ======================

const dbConfig = {
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'Clearway_Cyber_db',
    connectTimeout: 10000,
    charset: 'utf8mb4',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0
};

if (process.env.INSTANCE_CONNECTION_NAME) {
    dbConfig.socketPath = `/cloudsql/${process.env.INSTANCE_CONNECTION_NAME}`;
} else {
    dbConfig.host = process.env.DB_HOST || '127.0.0.1';
    dbConfig.port = process.env.DB_PORT || 3306;
}

const pool = mysql.createPool(dbConfig);

async function testDatabaseConnection() {
    try {
        const connection = await pool.getConnection();
        await connection.ping();
        connection.release();
        logger.info('✅ Database connected successfully!');
        return true;
    } catch (err) {
        logger.error('❌ Database connection failed:', {
            error: err.message,
            code: err.code
        });
        return false;
    }
}

global.dbConnection = pool;

// ======================
// 5. ENHANCED RATE LIMITING
// ======================

class EnhancedRateLimiter {
    constructor(windowMs, max, name = 'general') {
        this.windowMs = windowMs;
        this.max = max;
        this.name = name;
        this.hits = new Map();
    }

    middleware() {
        return (req, res, next) => {
            if (req.path === '/health') return next();
            
            const key = this.getKey(req);
            const now = Date.now();
            const windowStart = now - this.windowMs;
            
            if (!this.hits.has(key)) {
                this.hits.set(key, []);
            }
            
            const hitsInWindow = this.hits.get(key).filter(time => time > windowStart);
            
            if (hitsInWindow.length >= this.max) {
                logger.warn(`Rate limit exceeded for ${this.name}`, {
                    key,
                    path: req.path,
                    ip: req.ip,
                    attempts: hitsInWindow.length
                });
                
                // Add rate limit headers
                res.setHeader('X-RateLimit-Limit', this.max);
                res.setHeader('X-RateLimit-Remaining', 0);
                res.setHeader('X-RateLimit-Reset', new Date(windowStart + this.windowMs).toISOString());
                
                return res.status(429).json({ 
                    error: 'Too many requests. Please try again later.',
                    retryAfter: Math.ceil((this.windowMs - (now - windowStart)) / 1000)
                });
            }
            
            hitsInWindow.push(now);
            this.hits.set(key, hitsInWindow);
            
            // Add rate limit headers for successful requests
            res.setHeader('X-RateLimit-Limit', this.max);
            res.setHeader('X-RateLimit-Remaining', this.max - hitsInWindow.length);
            res.setHeader('X-RateLimit-Reset', new Date(windowStart + this.windowMs).toISOString());
            
            if (Math.random() < 0.01) this.cleanup();
            
            next();
        };
    }

    getKey(req) {
        if (this.name === 'login') {
            const email = req.body.email || 'unknown';
            return `${req.ip}:login:${email}`;
        } else if (this.name === 'sensitive') {
            const userId = req.user?.id || 'anonymous';
            return `${req.ip}:sensitive:${userId}:${req.path}`;
        }
        return `${req.ip}:${req.path}`;
    }

    cleanup() {
        const now = Date.now();
        const windowStart = now - this.windowMs;
        
        for (const [key, hits] of this.hits.entries()) {
            const recentHits = hits.filter(time => time > windowStart);
            if (recentHits.length === 0) {
                this.hits.delete(key);
            } else {
                this.hits.set(key, recentHits);
            }
        }
    }
}

// Create different limiters for different purposes
const globalLimiter = new EnhancedRateLimiter(15 * 60 * 1000, 200, 'global');
const loginLimiter = new EnhancedRateLimiter(15 * 60 * 1000, 10, 'login');
const sensitiveLimiter = new EnhancedRateLimiter(15 * 60 * 1000, 5, 'sensitive');

// Apply global rate limiting
app.use(globalLimiter.middleware());

// ======================
// 6. AUTHENTICATION MIDDLEWARE
// ======================

app.use((req, res, next) => {
    res.locals.error = req.query.error;
    res.locals.success = req.query.success;
    res.locals.user = null;

    // Enhanced JWT verification
    const token = req.cookies?.token;
    if (token) {
        try {
            const payload = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret');
            
            // Additional payload validation
            if (!payload.user || !payload.user.id || !payload.user.email) {
                throw new Error('Invalid token payload');
            }
            
            // Check token expiration with buffer
            if (payload.exp && Date.now() >= payload.exp * 1000 - 30000) { // 30 second buffer
                logger.debug('Token nearing expiration', { userId: payload.user.id });
            }
            
            res.locals.user = payload.user;
            req.user = payload.user;
        } catch (e) {
            logger.debug('JWT verification failed', { error: e.message });
            // Clear invalid token
            res.clearCookie('token');
        }
    } else if (req.session?.user) {
        res.locals.user = req.session.user;
        req.user = req.session.user;
    }

    next();
});

// ======================
// 7. ROUTES
// ======================

// Health check endpoint
app.get('/health', async (req, res) => {
    try {
        const dbStatus = await testDatabaseConnection();
        res.json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            database: dbStatus ? 'connected' : 'disconnected',
            environment: process.env.NODE_ENV || 'development',
            service: 'clearway-cyber',
            uptime: process.uptime(),
            version: '1.0.0'
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
    res.render('index');
});

app.get('/login', csrfProtection, (req, res) => {
    res.render('login', { csrfToken: req.csrfToken() });
});

app.get('/signup', csrfProtection, (req, res) => {
    res.render('signup', { csrfToken: req.csrfToken() });
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    req.session.destroy(() => {
        res.redirect('/login?success=Logged+out+successfully');
    });
});

// Profile endpoint with enhanced security
app.get('/profile', csrfProtection, (req, res) => {
    if (!res.locals.user) {
        logger.warn('Unauthenticated access to profile', { ip: req.ip });
        return res.redirect('/login?error=Please+login+first');
    }
    
    try {
        const token = req.csrfToken();
        res.render('profile', { 
            csrfToken: token,
            user: res.locals.user
        });
    } catch (error) {
        logger.error('CSRF token generation failed:', error);
        res.redirect('/?error=Security+error');
    }
});

// ======================
// 8. SECURE LOGIN ROUTE
// ======================

app.post('/login', loginLimiter.middleware(), csrfProtection, async (req, res) => {
    const { email = '', password = '' } = req.body;
    
    // Enhanced input validation
    if (!validatorLib.isEmail(String(email).trim()) || !password) {
        return res.redirect('/login?error=Invalid+login+credentials');
    }

    if (password.length > 100) {
        return res.redirect('/login?error=Invalid+credentials');
    }

    try {
        const [results] = await pool.execute(
            'SELECT id, email, password, name, bio FROM users WHERE email = ?',
            [email.trim()]
        );
        
        if (results.length === 0) {
            logger.warn('Login failed: user not found', { 
                email: email.substring(0, 3) + '***',
                ip: req.ip 
            });
            // Same error message to prevent user enumeration
            return res.redirect('/login?error=Invalid+login+credentials');
        }

        const user = results[0];
        const pepper = process.env.PEPPER || 'ClearwayCyberHardenedPepper2025';
        const ok = await bcrypt.compare(password + pepper, user.password);
        
        if (!ok) {
            logger.warn('Login failed: wrong password', { 
                email: email.substring(0, 3) + '***',
                ip: req.ip 
            });
            return res.redirect('/login?error=Invalid+login+credentials');
        }

        // Login successful
        logger.info('Login successful', { 
            userId: user.id, 
            email: email.substring(0, 3) + '***',
            ip: req.ip 
        });
        
        const payloadUser = { 
            id: user.id, 
            email: user.email, 
            name: user.name, 
            bio: user.bio 
        };
        
        const token = jwt.sign(
            { 
                user: payloadUser,
                iss: 'clearway-cyber',
                aud: 'clearway-webapp'
            }, 
            process.env.JWT_SECRET || 'fallback-secret',
            { 
                expiresIn: '2h',
                algorithm: 'HS256'
            }
        );
        
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 2 * 60 * 60 * 1000,
            path: '/'
        });
        
        req.session.user = payloadUser;
        res.redirect('/profile');
        
    } catch (error) {
        logger.error('Login error:', error);
        res.redirect('/login?error=Service+unavailable');
    }
});

// ======================
// 9. SECURE SIGNUP ROUTE
// ======================

app.post('/signup', csrfProtection, ids.idsMiddleware, async (req, res) => {
    try {
        let { email, password, name, bio = '' } = req.body;

        // Enhanced validation
        if (!email || !password || !name) {
            return res.redirect('/signup?error=All+fields+are+required');
        }

        email = email.trim();
        name = name.trim();
        
        if (!validatorLib.isEmail(email)) {
            return res.redirect('/signup?error=Invalid+email+address');
        }

        if (email.length > 255 || name.length > 100 || password.length > 100) {
            return res.redirect('/signup?error=Input+too+long');
        }

        const pwdCheck = validator.validatePassword(password);
        if (!pwdCheck.ok) {
            return res.redirect(`/signup?error=Weak+password+${pwdCheck.problems.join(',')}`);
        }

        // Sanitize inputs
        name = validatorLib.escape(name);
        bio = validatorLib.escape(bio.substring(0, 500)); // Limit bio length

        const pepper = process.env.PEPPER || 'ClearwayCyberHardenedPepper2025';
        const hashed = await bcrypt.hash(password + pepper, 12);

        await pool.execute(
            'INSERT INTO users (email, password, name, bio) VALUES (?, ?, ?, ?)',
            [email, hashed, name, bio]
        );

        logger.info('New user registered', { 
            email: email.substring(0, 3) + '***',
            ip: req.ip 
        });
        res.redirect('/login?success=Account+created+successfully');
        
    } catch (error) {
        logger.error('Signup error:', error);
        
        if (error.code === 'ER_DUP_ENTRY') {
            res.redirect('/signup?error=Email+already+exists');
        } else {
            res.redirect('/signup?error=Registration+failed');
        }
    }
});

// ======================
// 10. SECURE BIO UPDATE ROUTE (FIXED)
// ======================

app.post('/update-bio', csrfProtection, ids.idsMiddleware, sensitiveLimiter.middleware(), async (req, res) => {
    const user = res.locals.user;
    
    if (!user) {
        logger.warn('Unauthenticated bio update attempt', { ip: req.ip });
        return res.redirect('/login?error=Please+login+first');
    }

    const rawBio = req.body.bio || '';
    
    // Enhanced validation
    if (rawBio.length > 500) {
        return res.redirect('/profile?error=Bio+too+long+maximum+500+characters');
    }

    const bioCheck = validator.validateBio(rawBio);
    if (!bioCheck.ok) {
        logger.warn('Invalid bio content rejected', { 
            userId: user.id,
            reason: bioCheck.reason 
        });
        return res.redirect('/profile?error=Invalid+bio+content');
    }

    try {
        await pool.execute('UPDATE users SET bio = ? WHERE id = ?', [bioCheck.sanitized, user.id]);
        
        const updatedUser = { ...user, bio: bioCheck.sanitized };
        req.session.user = updatedUser;
        
        // Generate new token with updated bio
        const token = jwt.sign(
            { 
                user: updatedUser,
                iss: 'clearway-cyber',
                aud: 'clearway-webapp'
            }, 
            process.env.JWT_SECRET || 'fallback-secret',
            { 
                expiresIn: '2h',
                algorithm: 'HS256'
            }
        );
        
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 2 * 60 * 60 * 1000,
            path: '/'
        });
        
        logger.info('Bio updated successfully', { userId: user.id });
        res.redirect('/profile?success=Bio+updated+successfully');
        
    } catch (error) {
        logger.error('Bio update error:', { error: error.message, userId: user.id });
        res.redirect('/profile?error=Update+failed+please+try+again');
    }
});

// ======================
// 11. SECURE PASSWORD CHANGE ROUTE (CRITICAL FIX)
// ======================

app.post('/change-password', csrfProtection, ids.idsMiddleware, sensitiveLimiter.middleware(), async (req, res) => {
    const user = res.locals.user;
    
    if (!user) {
        logger.warn('Unauthenticated password change attempt', { ip: req.ip });
        return res.redirect('/login?error=Please+login+first');
    }

    const { currentPassword, newPassword, confirmPassword } = req.body;
    
    // Enhanced validation
    if (!currentPassword || !newPassword || !confirmPassword) {
        return res.redirect('/profile?error=All+fields+are+required');
    }

    if (newPassword !== confirmPassword) {
        return res.redirect('/profile?error=New+passwords+do+not+match');
    }

    if (currentPassword === newPassword) {
        return res.redirect('/profile?error=New+password+must+be+different');
    }

    if (newPassword.length < 8 || newPassword.length > 100) {
        return res.redirect('/profile?error=Password+must+be+8-100+characters');
    }

    const pwdCheck = validator.validatePassword(newPassword);
    if (!pwdCheck.ok) {
        return res.redirect(`/profile?error=Weak+password+${pwdCheck.problems.join(',')}`);
    }

    try {
        // 1. Verify current password
        const [results] = await pool.execute(
            'SELECT password FROM users WHERE id = ?',
            [user.id]
        );
        
        if (results.length === 0) {
            logger.error('User not found during password change', { userId: user.id });
            return res.redirect('/profile?error=User+not+found');
        }

        const currentHashedPassword = results[0].password;
        const pepper = process.env.PEPPER || 'ClearwayCyberHardenedPepper2025';
        const isCurrentValid = await bcrypt.compare(currentPassword + pepper, currentHashedPassword);
        
        if (!isCurrentValid) {
            logger.warn('Invalid current password attempt', { 
                userId: user.id,
                ip: req.ip 
            });
            return res.redirect('/profile?error=Current+password+is+incorrect');
        }

        // 2. Check password history (simplified - in production, implement proper password history)
        const isSameAsOld = await bcrypt.compare(newPassword + pepper, currentHashedPassword);
        if (isSameAsOld) {
            return res.redirect('/profile?error=New+password+cannot+be+same+as+current');
        }

        // 3. Hash and update new password
        const hashed = await bcrypt.hash(newPassword + pepper, 12);
        
        await pool.execute(
            'UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?',
            [hashed, user.id]
        );
        
        // 4. Invalidate all sessions and tokens
        res.clearCookie('token');
        res.clearCookie('_csrf');
        
        req.session.destroy((err) => {
            if (err) {
                logger.error('Session destruction error:', err);
            }
            
            logger.info('Password changed successfully, sessions invalidated', { 
                userId: user.id,
                ip: req.ip 
            });
            
            res.redirect('/login?success=Password+changed.+Please+login+again');
        });
        
    } catch (error) {
        logger.error('Password change error:', { 
            error: error.message,
            userId: user.id,
            ip: req.ip 
        });
        res.redirect('/profile?error=Password+change+failed');
    }
});

// ======================
// 12. API ENDPOINTS
// ======================

function requireAuthApi(req, res, next) {
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ 
            error: 'Unauthorized',
            code: 'TOKEN_MISSING'
        });
    }
    
    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret');
        
        if (!payload.user || !payload.user.id) {
            throw new Error('Invalid token payload');
        }
        
        req.user = payload.user;
        next();
    } catch (e) {
        logger.debug('API token verification failed', { error: e.message });
        res.status(401).json({ 
            error: 'Invalid token',
            code: 'TOKEN_INVALID'
        });
    }
}

app.get('/api/profile', requireAuthApi, (req, res) => {
    res.json({ 
        success: true,
        user: req.user,
        timestamp: new Date().toISOString()
    });
});

app.post('/api/update-bio', requireAuthApi, csrfProtection, sensitiveLimiter.middleware(), async (req, res) => {
    const rawBio = req.body.bio || '';
    const bioCheck = validator.validateBio(rawBio);
    
    if (!bioCheck.ok) {
        return res.status(400).json({ 
            error: 'Invalid bio content',
            code: 'BIO_INVALID',
            reason: bioCheck.reason
        });
    }

    try {
        await pool.execute('UPDATE users SET bio = ? WHERE id = ?', [bioCheck.sanitized, req.user.id]);
        
        const updatedUser = { ...req.user, bio: bioCheck.sanitized };
        
        // Generate new token
        const newToken = jwt.sign(
            { 
                user: updatedUser,
                iss: 'clearway-cyber',
                aud: 'clearway-webapp'
            }, 
            process.env.JWT_SECRET || 'fallback-secret',
            { 
                expiresIn: '2h',
                algorithm: 'HS256'
            }
        );
        
        res.json({ 
            success: true, 
            user: updatedUser, 
            token: newToken,
            message: 'Bio updated successfully'
        });
        
    } catch (error) {
        logger.error('API bio update error:', error);
        res.status(500).json({ 
            error: 'Update failed',
            code: 'UPDATE_FAILED'
        });
    }
});

// ======================
// 13. ERROR HANDLERS
// ======================

// 404 handler
app.use((req, res) => {
    logger.warn('404 Not Found', { 
        path: req.path, 
        method: req.method,
        ip: req.ip 
    });
    res.status(404).render('404');
});

// Enhanced global error handler
app.use((err, req, res, next) => {
    logger.error('Application error:', {
        error: err.message,
        stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
        path: req.path,
        method: req.method,
        code: err.code,
        ip: req.ip
    });

    if (err.code === 'EBADCSRFTOKEN') {
        if (req.path.startsWith('/api/')) {
            return res.status(403).json({ 
                error: 'Invalid security token',
                code: 'CSRF_TOKEN_INVALID'
            });
        }
        return res.redirect('/profile?error=Security+token+invalid.+Please+refresh');
    }

    if (req.path.startsWith('/api/')) {
        return res.status(500).json({ 
            error: 'Internal server error',
            code: 'INTERNAL_ERROR'
        });
    }

    res.redirect('/?error=Service+temporarily+unavailable');
});

// ======================
// 14. SERVER STARTUP
// ======================

const PORT = process.env.PORT || 8080;

// Start server with enhanced error handling
const server = app.listen(PORT, '0.0.0.0', async () => {
    logger.info('═══════════════════════════════════════════════════════════');
    logger.info('🚀 CLEARWAY CYBER - SECURITY HARDENED VERSION');
    logger.info('═══════════════════════════════════════════════════════════');
    logger.info(`📍 Server running on port: ${PORT}`);
    logger.info(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    logger.info(`🔌 Cloud Run: ${!!process.env.K_SERVICE}`);
    logger.info(`🔧 Trust proxy: ${app.get('trust proxy')}`);
    logger.info(`🔒 Security features: CSRF, Rate Limiting, Input Validation`);
    logger.info('✅ Ready for security testing.');
    logger.info('═══════════════════════════════════════════════════════════');
    
    // Test database connection
    await testDatabaseConnection();
});

// Handle server errors
server.on('error', (error) => {
    logger.error('Server error:', error);
    if (error.code === 'EADDRINUSE') {
        logger.error(`Port ${PORT} is already in use`);
        process.exit(1);
    }
});

// Export for testing
module.exports = app;