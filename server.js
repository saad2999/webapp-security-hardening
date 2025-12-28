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

/* ───────────────────────── LOGGER ───────────────────────── */

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) =>
            `${timestamp} [${level}] ${message}`
        )
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'security.log' }),
        new winston.transports.File({ filename: 'alerts.log', level: 'warn' })
    ]
});

app.set('logger', logger);

/* ───────────────────────── VIEW ENGINE ───────────────────────── */

app.use(expressLayout);
app.set('layout', 'layout');
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(morgan('dev'));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(cookieParser());

/* ───────────────────────── SECURITY ───────────────────────── */

app.use(helmet({
    hsts: { maxAge: 63072000, includeSubDomains: true, preload: true }
}));

app.use(cors({
    origin: process.env.ALLOWED_ORIGIN || 'http://localhost:3000',
    credentials: true
}));

/* ───────────────────────── SESSION ───────────────────────── */

app.use(session({
    secret: process.env.SESSION_SECRET || 'clearway-2025-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
    }
}));

/* ───────────────────────── RATE LIMIT ───────────────────────── */

app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200
}));

/* ───────────────────────── DATABASE (GCP SAFE) ───────────────────────── */

const pool = mysql.createPool({
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,

    ...(process.env.INSTANCE_CONNECTION_NAME
        ? {
            socketPath: `/cloudsql/${process.env.INSTANCE_CONNECTION_NAME}`
        }
        : {
            host: process.env.DB_HOST || '127.0.0.1',
            port: 3306
        })
});

logger.info('MySQL Pool initialized');

/* ───────────────────────── SAFE QUERY ───────────────────────── */

async function safeQuery(sql, params = []) {
    const conn = await pool.getConnection();
    try {
        const [rows] = await conn.execute(sql, params);
        return rows;
    } finally {
        conn.release();
    }
}

/* ───────────────────────── HEALTH CHECK ───────────────────────── */

app.get('/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({
            status: 'ok',
            time: Date.now(),
            database: 'connected'
        });
    } catch (err) {
        logger.warn('DB Health check failed');
        res.status(500).json({
            status: 'degraded',
            time: Date.now(),
            database: 'disconnected'
        });
    }
});

/* ───────────────────────── AUTH ───────────────────────── */

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret';
const PEPPER = process.env.PEPPER || 'pepper';
const SALT_ROUNDS = 12;

/* ───────────────────────── ROUTES ───────────────────────── */

app.get('/', (req, res) => res.render('index'));
app.get('/login', (req, res) => res.render('login'));
app.get('/signup', (req, res) => res.render('signup'));

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!validatorLib.isEmail(email)) {
        return res.redirect('/login?error=Invalid');
    }

    try {
        const users = await safeQuery(
            'SELECT * FROM users WHERE email = ?',
            [email]
        );

        if (!users.length) return res.redirect('/login?error=Invalid');

        const user = users[0];
        const ok = await bcrypt.compare(password + PEPPER, user.password);
        if (!ok) return res.redirect('/login?error=Invalid');

        const token = jwt.sign(
            { user: { id: user.id, email: user.email } },
            JWT_SECRET,
            { expiresIn: '2h' }
        );

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production'
        });

        res.redirect('/profile');
    } catch (e) {
        logger.error('Login failed');
        res.redirect('/login?error=Server');
    }
});

app.get('/profile', (req, res) => res.render('profile'));

/* ───────────────────────── GLOBAL ERROR ───────────────────────── */

app.use((err, req, res, next) => {
    logger.error(err.message);
    res.status(500).send('Internal Server Error');
});

/* ───────────────────────── START ───────────────────────── */

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
});
