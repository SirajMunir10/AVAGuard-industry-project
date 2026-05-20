$ErrorActionPreference = "Stop"

Write-Host "======================================"
Write-Host " AVAGuard Database Backup Utility     "
Write-Host "======================================"

Set-Location -Path "$PSScriptRoot"

# ── ENFORCE UTF-8 ENCODING ──
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUTF8 = 1

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFile = "backups\supabase_backup_$timestamp.json"

if (!(Test-Path "backups")) {
    New-Item -ItemType Directory -Force -Path "backups" | Out-Null
}

Write-Host "Exporting full database backup to $backupFile..."
# Using --output instead of > prevents encoding corruption
python manage.py dumpdata --natural-foreign --natural-primary -e contenttypes -e auth.Permission -e sessions.session -e admin.logentry --indent 4 --output $backupFile

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Database backup failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Backup completed!"
