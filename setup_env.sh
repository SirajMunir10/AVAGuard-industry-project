#!/bin/bash
echo "AVAGuard - Zero-to-Hero Environment Setup"
echo "============================================="

# 1. Check Python
python3 -c "import sys; print(f'Python version: {sys.version_info.major}.{sys.version_info.minor}')"

# 2. Create Virtual Environment
echo "Creating Virtual Environment (.venv)..."
python3 -m venv .venv

# 3. Activate Virtual Environment
echo "Activating Virtual Environment..."
source .venv/bin/activate

# 4. Upgrade pip
echo "Upgrading pip..."
python3 -m pip install --upgrade pip

# 5. Install avaguard-core
echo "Installing avaguard-core..."
pip install -e ./avaguard-core

# 6. Install avaguard-cli
echo "Installing avaguard-cli..."
pip install -e ./avaguard-cli

# 7. Install requirements.txt
echo "Installing dependencies from requirements.txt..."
pip install -r requirements.txt

# 8. Setup .env file
if [ ! -f web_portal/.env ]; then
    echo "Setting up web_portal/.env from .env.example..."
    cp web_portal/.env.example web_portal/.env
fi

# 9. Perform migrations
echo "Running database migrations..."
python3 web_portal/manage.py migrate

# 10. Create superuser if missing
echo "Provisioning admin user..."
python3 web_portal/manage.py create_superuser_if_missing

# 11. Initial mock data load
echo "Initializing initial dataset..."
python web_portal/manage.py seed_dev

echo "============================================="
echo "Setup Complete! You can now start the applications:"
echo "1. CLI Engine: python -m avaguard.cli scan"
echo "2. Web Portal: python web_portal/manage.py runserver"
echo "3. Desktop UI: python desktop_app/main.py"
