// Simple IDS/detection helpers
// Detect suspicious inputs (basic heuristics for SQLi/XSS patterns)

function isSuspiciousString(s) {
    if (!s) return false;
    const str = String(s);
    // common SQLi patterns and XSS tags
    const sqli = /('|"|--)\s*(or|and)\s+\d+=\d+/i;
    const sqli2 = /\b(union|select|insert|update|delete|drop)\b/i;
    const xss = /<script\b[^>]*>([\s\S]*?)<\/script>/i;
    const evalPattern = /javascript:|onerror=|onload=/i;
    return sqli.test(str) || sqli2.test(str) || xss.test(str) || evalPattern.test(str);
}

function isSuspiciousObject(obj) {
    if (!obj) return false;
    if (typeof obj === 'string') return isSuspiciousString(obj);
    if (typeof obj === 'object') {
        for (const k of Object.keys(obj)) {
            if (isSuspiciousString(obj[k])) return true;
        }
    }
    return false;
}

function detectSuspicious(req) {
    if (isSuspiciousObject(req.body)) return true;
    if (isSuspiciousObject(req.query)) return true;
    if (isSuspiciousObject(req.params)) return true;
    return false;
}

// middleware
function idsMiddleware(req, res, next) {
    try {
        if (detectSuspicious(req)) {
            // attach flag for logging
            req.suspicious = true;
            // do not block by default, just log and continue
            req.app && req.app.get('logger') && req.app.get('logger').warn('Suspicious input detected', { ip: req.ip, path: req.path });
        }
    } catch (e) {
        // ignore detection errors
    }
    next();
}

module.exports = { isSuspiciousString, detectSuspicious, idsMiddleware };
