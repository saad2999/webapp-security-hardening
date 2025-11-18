# Web Application Security Hardening – Cybersecurity Internship Task (November 2025)

## Overview
This repository completes the 3-week Cybersecurity Internship task by:
1. Assessing a deliberately vulnerable Node.js web application
2. Identifying critical vulnerabilities using manual testing + OWASP ZAP
3. Implementing industry-standard security fixes
4. Adding logging, rate limiting, and best practices

**Original Vulnerable App Used:** https://github.com/appsecco/vulnerable-node-application  
(Contains XSS, SQL Injection, plain-text passwords, no input validation, etc.)

## Vulnerabilities Found (Week 1)

| Vulnerability              | Risk  | Proof / Tool Used                  |
|----------------------------|-------|------------------------------------|
| Stored XSS                 | High  | OWASP ZAP + Manual `<script>alert('XSS')</script>` |
| Reflected XSS              | High  | Browser + ZAP                      |
| SQL Injection (Login Bypass)| High  | `admin' OR '1'='1`                 |
| Plain-text Password Storage| High  | Source code + database inspection  |
| Missing Security Headers   | Medium| OWASP ZAP + curl -I                |
| Insecure JWT Secret        | Medium| Hardcoded in source                |

→ Full OWASP ZAP reports (before & after) are in `/reports/`

## Security Fixes Implemented (Week 2 & 3)

| Fix                          | Library / Method Used                                 |
|--------------------------------|-------------------------------------------------------|
| Input Validation & Sanitization| `express-validator` + `validator.js`                 |
| Password Hashing               | `bcrypt` with 12 salt rounds                          |
| Secure Authentication          | `jsonwebtoken` + strong random secret in `.env`       |
| Secure HTTP Headers            | `helmet()`                                            |
| Logging & Monitoring           | `winston` (console + file)                            |
| Rate Limiting (Bonus)          | `express-rate-limit` on login & register             |
| Environment Variables          | `dotenv` for secrets                                  |

## Folder Structure
