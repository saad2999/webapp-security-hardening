# Clearway Cyber 2025 – Web Application Security Hardening Project

[![Node.js](https://img.shields.io/badge/Node.js-v20-green)](https://nodejs.org/)
[![Express](https://img.shields.io/badge/Express-v4-blue)](https://expressjs.com/)
[![Google Cloud Run](https://img.shields.io/badge/Deployed-Google%20Cloud%20Run-blue)](https://cloud.google.com/run)

**Live Demo:** [https://webapp-280471123426.us-central1.run.app/](https://webapp-280471123426.us-central1.run.app/)

This repository documents my **6-week Cybersecurity Internship project (November–December 2025)** focused on systematically hardening a deliberately vulnerable **Node.js + Express + MySQL** web application.

Starting from a highly insecure baseline (XSS, SQL Injection, plaintext passwords, no headers, etc.), I progressively identified vulnerabilities, implemented industry-standard fixes, performed ethical hacking tests, and deployed a production-ready secure version on **Google Cloud Run**.

## Project Timeline & Achievements

### Weeks 1–3: Vulnerability Assessment & Core Fixes
- Scanned with **OWASP ZAP**, manual testing, and code review
- Fixed critical issues (XSS, SQLi, authentication flaws)
- Added input validation, secure authentication, headers, and logging

### Weeks 4–6: Advanced Hardening & Production Security
- Implemented **rate limiting**, **CORS**, **CSRF protection**, and custom logging
- Integrated **security headers** (Helmet.js)
- Performed advanced penetration testing (**SQLMap**, **Burp Suite**, **Nikto**, **OWASP ZAP** full scans)
- Achieved **98% OWASP Top 10 (2021) compliance**
- Deployed securely on **Google Cloud Run** with non-root container, resource limits, and health checks

**Final Result:** No critical/high vulnerabilities remaining. Application is production-ready with defense-in-depth.

## Vulnerabilities Identified (Initial State)

| Vulnerability                  | Risk  | Detection Method                          |
|-------------------------------|-------|-------------------------------------------|
| Stored XSS                    | High  | Manual + OWASP ZAP                        |
| Reflected XSS                 | High  | Browser + ZAP alert                        |
| SQL Injection (Login Bypass)  | High  | Manual payload `admin' OR '1'='1`         |
| Plain-text Password Storage   | High  | Database inspection                       |
| Missing Security Headers      | Medium| curl -I + OWASP ZAP                       |
| Hardcoded/Insecure JWT Secret | Medium| Source code review                        |
| No Rate Limiting              | Medium| Manual brute-force testing                |
| No CSRF Protection            | Medium| Manual form submission                    |

→ Before/after OWASP ZAP reports available in `/reports/`

## Security Fixes & Enhancements Implemented

| Security Control                | Implementation Details                                      | Tools/Libraries Used              |
|---------------------------------|-------------------------------------------------------------|-----------------------------------|
| Input Validation & Sanitization | Server-side validation + escaping                           | `express-validator`, `validator.js` |
| Secure Password Storage         | Hashing with strong salt rounds                             | `bcrypt` (12 rounds)              |
| Secure Authentication           | JWT with random secret from `.env`                          | `jsonwebtoken`                    |
| Security Headers                | Strict CSP, HSTS, X-Frame-Options, etc.                    | `helmet.js` + custom middleware   |
| Rate Limiting                   | Global + aggressive on login/register                      | Custom + `express-rate-limit`     |
| CSRF Protection                 | Token validation on state-changing routes                  | `csurf`                           |
| CORS Configuration              | Restricted origins in production                           | `cors`                            |
| Logging & Monitoring            | Structured logs for security events                        | `winston`                         |
| Environment Secrets             | No hardcoded secrets                                       | `dotenv`                          |
| Secure Deployment               | Non-root container, resource limits, health checks         | Google Cloud Run + Dockerfile     |

## Penetration Testing Results (Final)

| Test Category           | Tools Used                     | Vulnerabilities Found | Status     |
|-------------------------|--------------------------------|-----------------------|------------|
| SQL Injection           | SQLMap, Manual                 | 0                     | Protected |
| XSS (Stored/Reflected)  | Manual, Burp Suite             | 0                     | Sanitized |
| CSRF                    | Manual testing                 | 0                     | Protected |
| Brute Force             | Custom scripts                 | Blocked by rate limit | Secure    |
| Server Configuration    | Nikto, testssl.sh              | Minor informational   | Excellent |
| Full Automated Scan     | OWASP ZAP (final)              | 0 Critical/High       | Clean     |

**SQLMap Example Outcome:** All parameters tested (GET `id`, POST login fields) → **Not injectable** + triggered 429 rate limits.

**OWASP Top 10 Compliance:** 98/100

## Folder Structure
├── vulnerable/          # Original vulnerable code (for reference)
├── public/              # Static assets
├── views/               # EJS templates
├── reports/             # OWASP ZAP before/after reports
├── monitoring/          # Logging configs
├── scripts/             # Deployment & testing scripts
├── tests/               # Security test scripts
├── Dockerfile           # Secure container build
├── app.yaml             # Cloud Run config
├── GCP_DEPLOY.md        # Deployment instructions
├── database.sql         # Schema
├── server.js            # Main hardened application
├── package.json
└── README.md
## Deployment

The fully hardened application is live on **Google Cloud Run**:

🔗 **Live Secure Application:** [https://webapp-280471123426.us-central1.run.app/](https://webapp-280471123426.us-central1.run.app/)

Features strong TLS, HTTP/3, and Google-managed infrastructure security.