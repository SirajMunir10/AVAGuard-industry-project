import os
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

class Command(BaseCommand):
    help = 'Creates a superuser if none exists'

    def handle(self, *args, **options):
        if os.environ.get('ENVIRONMENT', 'prod').lower() != 'dev' and os.environ.get('ALLOW_AUTO_SEED', 'false').lower() != 'true':
            self.stdout.write(self.style.WARNING('Skipping auto-superuser creation: Restricted in non-development environments.'))
            return
            
        User = get_user_model()
        if not User.objects.filter(is_superuser=True).exists():
            admin_email = os.environ.get('AVAGUARD_ADMIN_EMAIL', 'admin@avaguard.com')
            admin_pass = os.environ.get('AVAGUARD_ADMIN_PASSWORD', 'Admin123!')
            admin_first = os.environ.get('AVAGUARD_ADMIN_FIRST_NAME', 'Admin')
            # Use email-based creation — our User model has no username field
            user = User.objects.create_superuser(
                email=admin_email,
                password=admin_pass,
                first_name=admin_first,
            )
            self.stdout.write(self.style.SUCCESS(f'Superuser {admin_email} created successfully.'))
        else:
            self.stdout.write(self.style.SUCCESS('Superuser already exists.'))
