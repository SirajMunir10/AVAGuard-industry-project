$ErrorActionPreference = "Stop"

Write-Host "============================================="
Write-Host " AVAGuard Data Migration: SQLite -> Supabase "
Write-Host "============================================="

Set-Location -Path "$PSScriptRoot"

if (!(Test-Path ".env")) {
    Write-Host "Error: .env file not found."
    exit 1
}

# ── ENFORCE UTF-8 ENCODING ──
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUTF8 = 1

# Step 1: Backup .env
Write-Host "[1/5] Backing up .env configuration..."
Copy-Item -Path ".env" -Destination ".env.bak" -Force

try {
    # Step 2: Force SQLite connection
    Write-Host "[2/5] Temporarily swapping configuration to SQLite..."
    $envContent = Get-Content ".env"
    $envContent = $envContent -replace "DB_ENGINE=postgresql", "DB_ENGINE=sqlite3"
    Set-Content -Path ".env" -Value $envContent
    
    # Step 2.5: Ensure SQLite has all current migration tables applied
    Write-Host "[2.5/5] Applying missing schemas to SQLite before export..."
    python manage.py migrate
    if ($LASTEXITCODE -ne 0) {
        throw "SQLite pre-migration failed."
    }
    
    # Step 3: Export data
    Write-Host "[3/5] Exporting SQLite data to JSON... (this may take a moment)"
    # Using --output instead of PowerShell redirection (>) prevents cp1252 corruption of emojis/unicode
    python manage.py dumpdata --natural-foreign --natural-primary -e contenttypes -e auth.Permission -e sessions.session -e admin.logentry --indent 4 --output db_backup.json
    
    if ($LASTEXITCODE -ne 0) {
        throw "Python dumpdata failed. Export aborted."
    }
}
catch {
    Write-Host "CRITICAL ERROR during export step: $_" -ForegroundColor Red
    # Ensure cleanup before failing out
    if (Test-Path ".env.bak") {
        Copy-Item -Path ".env.bak" -Destination ".env" -Force
        Remove-Item -Path ".env.bak"
    }
    exit 1
}
finally {
    # Step 4: Restore Supabase connection
    Write-Host "[4/5] Restoring Supabase configuration..."
    if (Test-Path ".env.bak") {
        Copy-Item -Path ".env.bak" -Destination ".env" -Force
        Remove-Item -Path ".env.bak"
    }
}

# Step 5: Migrate and Load to Supabase
Write-Host "[5/5] Injecting data into Supabase..."
Write-Host "   -> Aligning schema schemas (migrate)..."
python manage.py migrate

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Django schema migrations failed. Aborting import phase." -ForegroundColor Red
    exit 1
}

Write-Host "   -> Importing data..."
python manage.py loaddata db_backup.json

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to import db_backup.json. Migration halted!" -ForegroundColor Red
    exit 1
}

Write-Host "============================================="
Write-Host " Migration Completed Successfully!           "
Write-Host " Your Supabase database is now populated.    "
Write-Host "============================================="
