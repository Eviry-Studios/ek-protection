# Security Policy — EK-Protection

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ Active  |
| < 1.0   | ❌ EOL     |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Report security issues via email:
- **contato@evirykorp.com**
- GPG key: available on request

Include:
1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

Response time: within 72 hours.

## Security Design Principles

### Authentication
- Passwords hashed with bcrypt, work factor 14
- Session tokens: 32-byte cryptographically random (`secrets.token_hex`)
- Constant-time comparison prevents timing attacks
- Progressive lockout: 5 failures → 15 min block

### Quarantine
- Files encrypted with Fernet (AES-128-CBC + HMAC-SHA256)
- Key stored separately (`quarantine.key`, chmod 600)
- Original file only removed after successful vault write verification
- Restore requires valid authenticated session

### IPC
- Unix socket, not TCP — local-only by design
- chmod 660 on socket file
- All IPC traffic is local JSON — no remote execution

### Signature Updates
- SHA-256 checksum verification before applying
- No code execution from remote — data only (JSON/JSONL)
- Partial updates fail safely — database not modified on error

### Logging
- All destructive operations logged with full context
- Logs stored in SQLite (tamper-evident via append)
- No sensitive data (passwords, keys) ever logged

## Known Limitations

1. Plugin system executes arbitrary Python — only load trusted plugins
2. ClamAV integration requires clamd running as root
3. Heuristic rules may produce false positives on legitimate packed software

## Threat Model

EK-Protection protects against:
- ✅ Known malware (signature matching)
- ✅ Malicious scripts (heuristic rules)
- ✅ Dropper patterns (download+execute)
- ✅ Persistence mechanisms (cron, hidden files)
- ✅ Privilege escalation attempts

EK-Protection does NOT protect against:
- ❌ Kernel-level rootkits (requires kernel module)
- ❌ Zero-day exploits not matching any heuristic
- ❌ Encrypted network C2 (traffic not inspected)
