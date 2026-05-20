# AVAGuard — Azure CIS Benchmark Compliance Platform

AVAGuard is an enterprise-grade compliance scanner for Microsoft 365 and Azure environments. It maps tenant settings against CIS benchmarks and provides automated reporting, remediation guidance, and trend analysis.

**Current Version:** `0.1.0`

---

## 🏗️ Architecture

| Module | Purpose |
|---|---|
| `avaguard-core/` | Headless engine — checks, scoring, reporting, retry logic, ThreadPool execution |
| `avaguard-cli/` | Click-based CLI — `scan`, `health`, `compare` commands |
| `desktop_app/` | PyQt6 cross-platform desktop GUI |
| `web_portal/` | Django dashboard — user management, scan history, role-based access |
| `mock_data/` | Pre-generated enterprise dataset for testing without Azure credentials |

---

## ⚡ Quick Start

### 1. Clone & Set Up

```bash
git clone https://github.com/Ahmed-Mujtaba007/avaguard-python.git
cd avaguard-python
```

**Windows:**
```powershell
.\setup_env.ps1
```

**Linux/Mac:**
```bash
./setup_env.sh
```

### 2. Configure Environment

```bash
# Web portal config
cp web_portal/.env.example web_portal/.env

# CLI config
cp config.example.ini config.ini
```

### 3. Initialize Database & Run

```bash
# Apply migrations & seed data
python web_portal/manage.py migrate
python web_portal/manage.py seed_dev
python web_portal/manage.py create_superuser_if_missing

# Start the web portal
python web_portal/manage.py runserver
```

---

## 🖥️ CLI Commands

```bash
# System health check
python -m avaguard.cli health

# Run a mock scan (no Azure credentials needed)
python -m avaguard.cli scan --mock

# Compare two scan results
python -m avaguard.cli compare scan_a.json scan_b.json

# Run with live Azure credentials
python -m avaguard.cli scan
```

---

## 🗄️ Database Setup

### SQLite (Default — Local Development)

Zero configuration. Just run `python web_portal/manage.py migrate` and you're ready. This is the default for local development and the desktop app.

### PostgreSQL via Supabase (Team / Production)

For team collaboration or production, connect to a Supabase project:

1. **Create a Supabase project** at [supabase.com](https://supabase.com)
2. Go to **Settings → Database** and copy the connection details
3. Edit `web_portal/.env`:

```env
DB_ENGINE=postgresql
DB_NAME=postgres
DB_USER=postgres.YOUR_PROJECT_REF
DB_PASSWORD=YOUR_SUPABASE_DB_PASSWORD 
DB_HOST=aws-0-us-east-1.pooler.supabase.com
DB_PORT=6543
DB_SSLMODE=require
```




4. Run migrations:
```bash
python web_portal/manage.py migrate
python web_portal/manage.py seed_dev
python web_portal/manage.py create_superuser_if_missing
```

> **How it works:** `settings.py` reads `DB_ENGINE` from `.env`. If set to `postgresql`, it connects to your Supabase PostgreSQL instance. Otherwise it defaults to local SQLite.

### Team Collaboration (Sharing Supabase Access)

Because your `.env` file containing database credentials is not pushed to GitHub, your team members need to complete these steps to collaborate using the same database:

1. **Project Owner:** Go to the Supabase Dashboard, click the **Settings** gear → **Organization/Team → Members**, and invite your team member's email.
2. **Team Member:** Clone the repository from GitHub.
3. **Team Member:** Create a new `web_portal/.env` file locally.
4. **Team Member:** Accept the Supabase invite, log into the dashboard, go to **Project Settings → Database**, and retrieve the connection strings to paste into their local `.env` file.

*Now, when they start the server, they will automatically be connected to the shared database.*

### Database Backup & Sync (Optional)

```bash
# Export current state (PostgreSQL)
pg_dump -h HOST -U USER -d DB_NAME > dump.sql

# Import on another machine
psql -h HOST -U USER -d DB_NAME < dump.sql
```

---

## 🧪 Running Tests

```bash
pytest avaguard-core/tests/ avaguard-cli/tests/ desktop_app/tests/ -v
```

---

## 📁 Project Structure

```
avaguard-python/
├── avaguard-core/          # Engine: checks, scoring, retry, ThreadPool
│   ├── avaguard_core/
│   │   ├── checks/         # 10 CIS benchmark checks
│   │   ├── templates/      # Jinja2 report templates
│   │   ├── engine.py       # ScanEngine with ThreadPoolExecutor
│   │   ├── compare.py      # Scan diff engine
│   │   └── ...
│   └── tests/
├── avaguard-cli/           # CLI: scan, health, compare
│   ├── avaguard/
│   │   ├── cli.py          # Click commands
│   │   ├── health.py       # HealthChecker class
│   │   └── config.py       # Config reader
│   └── tests/
├── desktop_app/            # PyQt6 desktop GUI
│   ├── main.py
│   ├── views/
│   ├── workers/
│   └── ui/
├── web_portal/             # Django dashboard
│   ├── config/settings.py  # Dual DB support (SQLite + PostgreSQL)
│   ├── core/               # Views, models, middleware
│   ├── api/                # REST API endpoints
│   ├── templates/
│   └── fixtures/dev_seed.json
├── mock_data/              # Enterprise test dataset
├── requirements.txt        # Consolidated dependencies
├── config.example.ini      # CLI config template
├── setup_env.ps1           # Windows setup script
├── setup_env.sh            # Linux/Mac setup script
└── VERSION                 # Version file (0.1.0)
```

---

## 🔐 Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | dev-insecure-key | Django secret key (change in production) |
| `DEBUG` | `True` | Django debug mode |
| `DB_ENGINE` | `sqlite3` | `sqlite3` or `postgresql` |
| `DB_NAME` | `postgres` | PostgreSQL database name |
| `DB_USER` | `postgres` | PostgreSQL user |
| `DB_PASSWORD` | *(empty)* | PostgreSQL password |
| `DB_HOST` | `localhost` | PostgreSQL host |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_SSLMODE` | `require` | SSL mode for PostgreSQL |
| `OTP_ENABLED` | `False` | Enable 2FA/MFA enforcement |
| `EMAIL_HOST_USER` | *(empty)* | Gmail address for OTP emails |
| `EMAIL_HOST_PASSWORD` | *(empty)* | Gmail app password |

---

## 📋 License

Private repository — all rights reserved.
