Write-Host "AVAGuard - Zero-to-Hero Environment Setup"
Write-Host "============================================="

# 1. Check Python version
$pythonVersion = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
Write-Host "Python version: $pythonVersion"

# 2. Create Virtual Environment
Write-Host "Creating Virtual Environment (.venv)..."
python -m venv .venv

# 3. Activate Virtual Environment
Write-Host "Activating Virtual Environment..."
. .venv\Scripts\Activate.ps1

# 4. Upgrade pip
Write-Host "Upgrading pip..."
python -m pip install --upgrade pip

# 5. Install avaguard-core
Write-Host "Installing avaguard-core..."
pip install -e ./avaguard-core

# 6. Install avaguard-cli
Write-Host "Installing avaguard-cli..."
pip install -e ./avaguard-cli

# 7. Install requirements.txt
Write-Host "Installing dependencies from requirements.txt..."
pip install -r requirements.txt

# 8. Setup .env file
if (-not (Test-Path web_portal\.env)) {
    Write-Host "Setting up web_portal\.env from .env.example..."
    Copy-Item -Path web_portal\.env.example -Destination web_portal\.env
}

# 9. Perform migrations
Write-Host "Running database migrations..."
python web_portal/manage.py migrate

# 10. Create superuser if missing
Write-Host "Provisioning admin user..."
python web_portal/manage.py create_superuser_if_missing

# 11. Initial mock data load
Write-Host "Initializing initial dataset..."
python web_portal/manage.py seed_dev

Write-Host "============================================="
Write-Host "Setup Complete! You can now start the applications:"
Write-Host "1. CLI Engine: python -m avaguard.cli scan"
Write-Host "2. Web Portal: python web_portal/manage.py runserver"
Write-Host "3. Desktop UI: python desktop_app/main.py"
