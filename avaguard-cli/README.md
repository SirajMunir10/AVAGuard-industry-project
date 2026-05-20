# AVAGuard - Azure CIS Benchmark Compliance Checker

**Phase 1: CLI Prototype**  
**Version:** 0.1.0  
**Author:** Ahmed Mujtaba  
**University:** Foundation University, School of Science & Technology

## Overview

AVAGuard is an automated compliance checking tool that validates Azure Active Directory (Azure AD) configurations against the CIS Microsoft Azure Foundations Benchmark v2.0.0. This CLI prototype performs security audits and generates detailed compliance reports.

## Features

- ✅ **10 CIS Benchmark Checks** covering Azure AD security controls
- 🔐 **Secure Authentication** via Azure AD App Registration
- 📊 **Dual Report Formats** (HTML & JSON)
- 🎯 **Tier-Based Scanning** (Free vs Premium Azure AD)
- 🚀 **Fast Execution** with intelligent retry logic
- 📈 **Detailed Remediation Guidance** for failed checks

## Supported CIS Controls

### Free Tier Compatible
- **1.3** - Security Defaults enabled
- **1.5** - No guest users with elevated roles
- **1.11** - Legacy authentication blocked
- **1.23** - No custom subscription owner roles
- **2.1** - Only approved domains used
- **password_age** - Password age validation

### Premium Tier Required
- **1.1** - MFA for privileged users (requires Premium P1)
- **1.8** - Self-service password reset enabled (requires Premium P1)
- **3.1** - Sign-in risk policy configured (requires Premium P2)
- **inactive_users** - Inactive user detection (requires Premium)

## Prerequisites

- **Python 3.9+**
- **Azure AD Tenant** (Free or Premium)
- **Azure AD App Registration** with required permissions
- **Microsoft Graph API Permissions:**
  - `User.Read.All`
  - `Group.Read.All`
  - `RoleManagement.Read.Directory`
  - `Policy.Read.All`
  - `Organization.Read.All`
  - `Domain.Read.All`
  - `AuditLog.Read.All` (Premium only)
  - `Policy.Read.ConditionalAccess` (Premium only)

## Installation

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/avaguard-cli.git
cd avaguard-cli
```

### 2. Create Virtual Environment
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Install AVAGuard
```bash
pip install -e .
```

## Configuration

### 1. Create App Registration in Azure Portal

1. Go to **Azure Active Directory** → **App registrations** → **New registration**
2. Name: `AVAGuard-Scanner`
3. Click **Register**
4. Note the **Application (client) ID** and **Directory (tenant) ID**

### 2. Create Client Secret

1. Go to **Certificates & secrets** → **New client secret**
2. Description: `AVAGuard-CLI-Secret`
3. Expires: 24 months
4. **Copy the secret value immediately**

### 3. Grant API Permissions

1. Go to **API permissions** → **Add a permission**
2. Select **Microsoft Graph** → **Application permissions**
3. Add the permissions listed in Prerequisites
4. Click **Grant admin consent for [Your Tenant]**

### 4. Configure AVAGuard

Copy the example config file:
```bash
cp config.example.ini config.ini
```

Edit `config.ini` with your credentials:
```ini
[azure]
tenant_id = YOUR_TENANT_ID
client_id = YOUR_CLIENT_ID
client_secret = YOUR_CLIENT_SECRET

[scan]
tier = free  # or 'premium'
```

⚠️ **NEVER commit config.ini to version control!**

## Usage

### Test Connection
```bash
avaguard test-connection
```

### List Available Checks
```bash
avaguard list-checks
```

### Run Full Scan
```bash
# Run all checks appropriate for your tier
avaguard scan

# Run specific checks
avaguard scan --checks 1.3,1.5,1.11

# Run only free tier checks
avaguard scan --tier free

# Run with custom output format
avaguard scan --output html
```

### Command-Line Options

```
Options:
  -c, --checks TEXT     Comma-separated check IDs (e.g., 1.1,1.3,1.5)
  -t, --tier TEXT       Run checks for tier: free, premium, or all
  -o, --output TEXT     Output format: html, json, or both
  --config-file TEXT    Path to config file (default: config.ini)
```

## Output

### Terminal Output
Colored, real-time progress with summary:
```
[1/6] Running check 1.3: Ensure Security Defaults is enabled...
    ✓ PASS - Security Defaults is enabled

Scan Summary:
  Total Checks: 6
  Passed: 5
  Failed: 1
  Errors: 0
  Overall Score: 83.3%
```

### HTML Report
Professional, interactive report with:
- Executive summary dashboard
- Detailed check results
- Non-compliant resource tables
- Remediation guidance

### JSON Report
Machine-readable format for:
- Integration with other tools
- Historical analysis
- Custom reporting

## Project Structure

```
avaguard-cli/
├── avaguard/
│   ├── __init__.py
│   ├── auth.py              # Azure authentication
│   ├── cli.py               # CLI interface
│   ├── config.py            # Configuration management
│   ├── graph_client.py      # Graph API wrapper
│   ├── reporter.py          # Report generation
│   └── checks/              # CIS compliance checks
│       ├── __init__.py
│       ├── base_check.py
│       ├── check_1_1_mfa.py
│       ├── check_1_3_security_defaults.py
│       └── ...
├── output/
│   ├── reports/             # Generated reports
│   └── logs/                # Application logs
├── tests/                   # Unit tests
├── config.ini               # Your credentials (gitignored)
├── config.example.ini       # Template
├── requirements.txt
├── setup.py
└── README.md
```

## Development

### Running Tests
```bash
pytest tests/ -v --cov=avaguard
```

### Adding New Checks

1. Create new file in `avaguard/checks/`:
```python
from avaguard.checks.base_check import BaseCheck, CheckResult, CheckStatus

class CheckCustom(BaseCheck):
    CHECK_ID = "custom_1"
    TITLE = "Your check title"
    REQUIRES_PREMIUM = False
    
    def execute(self) -> CheckResult:
        # Your check logic here
        pass
```

2. Register in `avaguard/checks/__init__.py`:
```python
AVAILABLE_CHECKS = {
    'custom_1': CheckCustom,
    # ...
}
```

## Troubleshooting

### Authentication Errors

**Error:** "Failed to acquire token: AADSTS700016"
- **Solution:** Ensure admin consent is granted for API permissions

**Error:** "Insufficient privileges"
- **Solution:** Verify all required Graph API permissions are added and consented

### API Errors

**Error:** "429 Too Many Requests"
- **Solution:** Tool automatically retries with backoff. If persists, reduce scan frequency.

**Error:** "Premium license required"
- **Solution:** Set `tier = free` in config.ini or upgrade Azure AD subscription

### General Issues

**Check logs:**
```bash
cat output/logs/avaguard.log
```

**Validate configuration:**
```bash
avaguard test-connection
```

## Security Best Practices

- ✅ Store credentials in `config.ini` (gitignored)
- ✅ Use principle of least privilege for API permissions
- ✅ Rotate client secrets regularly (every 6-12 months)
- ✅ Monitor App Registration sign-in logs
- ❌ Never commit credentials to version control
- ❌ Never share client secrets in plain text

## Roadmap

### Phase 2 (Desktop Application)
- Windows GUI with PyQt6
- Real-time dashboard
- Local database for scan history

### Phase 3 (Web Portal)
- Browser-based interface
- Multi-user support
- Centralized reporting

### Phase 4 (Enterprise Features)
- Continuous monitoring
- AI-driven remediation
- Multi-cloud support (AWS, GCP)

## License

This project is developed as an academic prototype for Foundation University.

## Support

For issues or questions:
- Create an issue on GitHub
- Contact: [Your Email]

## Acknowledgments

- CIS for Azure Foundations Benchmark
- Microsoft for Graph API documentation
- Foundation University for project support

---

**⚠️ Disclaimer:** This tool is for educational and compliance auditing purposes. Always test in non-production environments first.