import os
import shutil
from datetime import datetime
from pathlib import Path
from django.core.management.base import BaseCommand
from django.conf import settings

class Command(BaseCommand):
    help = 'Backups the SQLite database'

    def add_arguments(self, parser):
        parser.add_argument('--output-dir', type=str, default='backups', help='Output directory for backups')

    def handle(self, *args, **options):
        output_dir = Path(settings.BASE_DIR) / options['output_dir']
        output_dir.mkdir(parents=True, exist_ok=True)
        
        db_path = Path(settings.BASE_DIR) / 'db.sqlite3'
        if not db_path.exists():
            self.stdout.write(self.style.ERROR('Database file does not exist.'))
            return
            
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f'db_backup_{timestamp}.sqlite3'
        backup_path = output_dir / backup_name
        
        shutil.copy2(db_path, backup_path)
        self.stdout.write(self.style.SUCCESS(f'Successfully backed up database to {backup_path}'))
        
        # Enforce 10 backup limit
        backups = sorted(output_dir.glob('db_backup_*.sqlite3'), key=os.path.getmtime)
        while len(backups) > 10:
            oldest = backups.pop(0)
            oldest.unlink()
            self.stdout.write(self.style.WARNING(f'Deleted old backup {oldest.name} to enforce retention limit.'))
