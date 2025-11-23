// Simple validation and sanitization helpers
// Use these to validate user input before writing to the DB or rendering.
// These are intentionally lightweight and dependency-free.

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

function sanitize(str) {
    if (str == null) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;')
        .replace(/\//g, '&#x2F;');
}

function validateEmail(email) {
    if (!email) return { ok: false, reason: 'empty' };
    const ok = EMAIL_RE.test(String(email).trim());
    return { ok, reason: ok ? null : 'invalid' };
}

function validatePassword(password, options = {}) {
    // options: minLength (default 8)
    const minLength = options.minLength || 8;
    const pw = String(password || '');
    const problems = [];
    if (pw.length < minLength) problems.push(`min:${minLength}`);
    if (!/[0-9]/.test(pw)) problems.push('digit');
    if (!/[a-z]/.test(pw)) problems.push('lower');
    if (!/[A-Z]/.test(pw)) problems.push('upper');
    if (!/[\W_]/.test(pw)) problems.push('symbol');
    return { ok: problems.length === 0, problems };
}

function validateName(name, options = {}) {
    const min = options.min || 1;
    const max = options.max || 100;
    const n = String(name || '').trim();
    if (n.length < min) return { ok: false, reason: 'too-short' };
    if (n.length > max) return { ok: false, reason: 'too-long' };
    return { ok: true };
}

function validateBio(bio, options = {}) {
    const max = options.max || 500;
    const s = String(bio || '');
    if (s.length > max) return { ok: false, reason: 'too-long' };
    // return sanitized version to use when storing or rendering
    return { ok: true, sanitized: sanitize(s) };
}

module.exports = {
    sanitize,
    validateEmail,
    validatePassword,
    validateName,
    validateBio,
};
