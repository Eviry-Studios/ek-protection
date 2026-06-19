# EK-Protection

<p align="center">
  <img src="assets/logo.png" alt="EK-Protection Logo" width="180">
</p>

> Terminal-based antivirus daemon for Linux — lightweight, modular, professional.

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange.svg)]()

---

## Features (v1.0 Roadmap)

- **Real-time monitoring** — inotify-based file and process surveillance
- **On-demand scanning** — quick scan, full scan, custom path
- **Threat detection** — SHA-256 signature matching + heuristic analysis
- **Secure quarantine** — encrypted vault, full restoration capability
- **Authentication** — bcrypt password protection for critical operations
- **Exceptions system** — whitelist by path, hash, process, or extension
- **Structured logs** — SQLite + rotating files + JSON events
- **systemd integration** — auto-start on boot
- **Plugin architecture** — extend detection with custom modules
- **ClamAV integration** — optional complementary engine (Patch 10)

## Installation

### Quick install (recommended for end users)

One command, asks for nothing, sets up everything including the systemd service:

```bash
curl -fsSL https://raw.githubusercontent.com/Eviry-Studios/ek-protection/main/install.sh | sudo bash
```

### Manual install (for development)

```bash
git clone https://github.com/Eviry-Studios/ek-protection
cd ek-protection

python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

sudo ekp init
```

## Quick Start

```bash
# First time only: set your password
sudo ekp auth setup

# Start as a background service (survives reboot)
sudo systemctl enable --now ek-protection

# Check status
ekp status

# View configuration
ekp config show

# Set a config value
ekp config set daemon.log_level DEBUG
```

## Development

```bash
# Run tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=ekprotection --cov-report=term-missing

# Lint
ruff check ekprotection/

# Type check
mypy ekprotection/
```

## Architecture

See [docs/architecture.md](docs/architecture.md) for the full component diagram and data flow.

## Patch Status

| Patch | Feature | Status |
|-------|---------|--------|
| 1 | Base structure + CLI + config | ✅ |
| 2 | Authentication | 📋 |
| 3 | Logging | 📋 |
| 4 | Real-time monitor | 📋 |
| 5 | Exceptions | 📋 |
| 6 | Quarantine | 📋 |
| 7 | Scanner | 📋 |
| 8 | Heuristics | 📋 |
| 9 | Daemon IPC + systemd | 📋 |
| 10 | v1.0 stable | 📋 |

## License

MIT — see [LICENSE](LICENSE)

## Author

[EviRyKorp](https://github.com/Eviry-Studios)
