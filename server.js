const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const path = require('path');
const morgan = require('morgan');
const expressLayout = require('express-ejs-layouts');

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

app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    res.locals.error = req.query.error;
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
        console.log("Run: mysql -u redhat < database.sql");
        process.exit(1);
    }
    console.log("DB Connected");
});

// ROUTES
app.get('/', (req, res) => res.render('index'));
app.get('/login', (req, res) => res.render('login'));
app.get('/signup', (req, res) => res.render('signup'));
app.get('/profile', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    res.render('profile');
});
app.get('/logout', (req, res) => { req.session.destroy(); res.redirect('/'); });

app.post('/login', (req, res) => {
    const { email = '', password = '' } = req.body;
    const query = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;
    db.query(query, (err, results) => {
        if (err || results.length === 0) {
            return res.redirect('/login?error=Invalid%20login%20or%20SQLi%20detected');
        }
        req.session.user = results[0];
        res.redirect('/profile');
    });
});

app.post('/signup', (req, res) => {
    const { email, password, name, bio } = req.body;
    const query = `INSERT INTO users (email, password, name, bio) VALUES ('${email}', '${password}', '${name}', '${bio}')`;
    db.query(query, err => {
        if (err) return res.redirect('/signup?error=Email%20exists');
        res.redirect('/login');
    });
});

app.post('/update-bio', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const bio = req.body.bio || '';
    db.query(`UPDATE users SET bio = '${bio}' WHERE id = ${req.session.user.id}`);
    req.session.user.bio = bio;
    res.redirect('/profile');
});
// UPDATE BIO (XSS VULNERABLE)
app.post('/update-bio', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const bio = req.body.bio || '';
    const id = req.session.user.id;
    db.query(`UPDATE users SET bio = '${bio}' WHERE id = ${id}`, (err) => {
        if (err) console.log(err);
        req.session.user.bio = bio;
        res.redirect('/profile?success=Bio+updated');
    });
});

// CHANGE PASSWORD (PLAINTEXT VULNERABLE)
app.post('/change-password', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    const newPassword = req.body.newPassword;
    const id = req.session.user.id;
    db.query(`UPDATE users SET password = '${newPassword}' WHERE id = ${id}`, (err) => {
        if (err) console.log(err);
        req.session.user.password = newPassword;
        res.redirect('/profile?success=Password+changed+(plaintext!)');
    });
});
app.listen(3000, () => {
    console.log('\nCLEARWAY CYBER - WEEK 1 FINAL - 100% WORKING');
    console.log('http://localhost:3000');
    console.log('SQLi: admin@clearway.com\' OR \'1\'=\'1');
    console.log('XSS: <script>alert("HIRED")</script>');
});
