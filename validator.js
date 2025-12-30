// Enhanced validation and sanitization helpers
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const SUSPICIOUS_PATTERNS = [
    /<script\b[^>]*>/i,
    /javascript:/i,
    /data:text\/html/i,
    /on\w+\s*=/i,
    /vbscript:/i,
    /expression\s*\(/i,
    /url\s*\(/i,
    /eval\s*\(/i,
    /document\./i,
    /window\./i,
    /alert\s*\(/i,
    /confirm\s*\(/i,
    /prompt\s*\(/i,
    /<\?php/i,
    /<\/?\w+.*?>/i // Basic HTML tags
];

function sanitize(str) {
    if (str == null) return '';
    
    const sanitized = String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;')
        .replace(/\//g, '&#x2F;')
        .replace(/\\/g, '&#x5C;')
        .replace(/`/g, '&#x60;');
    
    // Additional security: remove control characters
    return sanitized.replace(/[\x00-\x1F\x7F]/g, '');
}

function validateEmail(email) {
    if (!email || typeof email !== 'string') {
        return { ok: false, reason: 'invalid' };
    }
    
    const trimmedEmail = email.trim();
    
    if (trimmedEmail.length > 255) {
        return { ok: false, reason: 'too-long' };
    }
    
    if (trimmedEmail.includes('..') || trimmedEmail.includes(' ')) {
        return { ok: false, reason: 'invalid' };
    }
    
    const ok = EMAIL_RE.test(trimmedEmail);
    return { ok, reason: ok ? null : 'invalid' };
}

function validatePassword(password, options = {}) {
    if (!password || typeof password !== 'string') {
        return { ok: false, problems: ['missing'] };
    }
    
    const minLength = options.minLength || 8;
    const maxLength = options.maxLength || 100;
    const pw = password;
    const problems = [];
    
    if (pw.length < minLength) problems.push(`min-length-${minLength}`);
    if (pw.length > maxLength) problems.push(`max-length-${maxLength}`);
    if (!/[0-9]/.test(pw)) problems.push('digit');
    if (!/[a-z]/.test(pw)) problems.push('lowercase');
    if (!/[A-Z]/.test(pw)) problems.push('uppercase');
    if (!/[\W_]/.test(pw)) problems.push('special');
    
    // Check for common weak passwords
    const commonPasswords = [
        'password', '123456', 'qwerty', 'admin', 'welcome',
        'password123', 'letmein', 'monkey', 'dragon', 'sunshine'
    ];
    
    if (commonPasswords.includes(pw.toLowerCase())) {
        problems.push('common');
    }
    
    // Check for sequential characters
    if (/(.)\1\1/.test(pw)) {
        problems.push('sequential');
    }
    
    return { ok: problems.length === 0, problems };
}

function validateName(name, options = {}) {
    if (!name || typeof name !== 'string') {
        return { ok: false, reason: 'invalid' };
    }
    
    const min = options.min || 1;
    const max = options.max || 100;
    const n = name.trim();
    
    if (n.length < min) return { ok: false, reason: 'too-short' };
    if (n.length > max) return { ok: false, reason: 'too-long' };
    
    // Check for suspicious patterns in names
    for (const pattern of SUSPICIOUS_PATTERNS) {
        if (pattern.test(n)) {
            return { ok: false, reason: 'suspicious' };
        }
    }
    
    return { ok: true };
}

function validateBio(bio, options = {}) {
    if (bio == null) bio = '';
    
    const max = options.max || 500;
    const s = String(bio).trim();
    
    // Length check
    if (s.length > max) {
        return { ok: false, reason: 'too-long', sanitized: '' };
    }
    
    // Check for suspicious patterns
    for (const pattern of SUSPICIOUS_PATTERNS) {
        if (pattern.test(s)) {
            return { ok: false, reason: 'suspicious-content', sanitized: '' };
        }
    }
    
    // Check for SQL injection patterns (basic)
    const sqlPatterns = [
        /(\'|\")(.*)(\-\-)/i,
        /(\'|\")(.*)(or|and)(.*)\=(\'|\")/i,
        /union(.*)select/i,
        /insert(.*)into/i,
        /update(.*)set/i,
        /delete(.*)from/i,
        /drop(.*)table/i,
        /create(.*)table/i,
        /exec(\s|\+)+(s|x)p\w+/i
    ];
    
    for (const pattern of sqlPatterns) {
        if (pattern.test(s)) {
            return { ok: false, reason: 'suspicious-content', sanitized: '' };
        }
    }
    
    // Return sanitized version
    return { ok: true, sanitized: sanitize(s) };
}

// New function to validate input for XSS
function validateForXSS(input, maxLength = 1000) {
    if (input == null) return { ok: false, reason: 'empty' };
    
    const str = String(input);
    
    if (str.length > maxLength) {
        return { ok: false, reason: 'too-long' };
    }
    
    for (const pattern of SUSPICIOUS_PATTERNS) {
        if (pattern.test(str)) {
            return { ok: false, reason: 'xss-detected' };
        }
    }
    
    return { ok: true };
}

module.exports = {
    sanitize,
    validateEmail,
    validatePassword,
    validateName,
    validateBio,
    validateForXSS
};