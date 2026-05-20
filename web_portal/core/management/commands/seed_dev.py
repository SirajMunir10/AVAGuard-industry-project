"""
AVAGuard - Load Dev Seed Data

Creates default organization, users (one per role), and sample scans.
Safe to run multiple times - skips existing records.

Usage:
    python manage.py seed_dev
"""

from django.core.management.base import BaseCommand
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from datetime import timedelta
import uuid
from core.models import Organization, User, ScanSummary, AuditLog


DEFAULT_PASSWORD = 'Admin12345!'


class Command(BaseCommand):
    help = 'Load development seed data (org, 4 users, sample scans)'

    def handle(self, *args, **options):
        import os
        if os.environ.get('ENVIRONMENT', 'prod').lower() != 'dev' and os.environ.get('ALLOW_AUTO_SEED', 'false').lower() != 'true':
            self.stdout.write(self.style.WARNING('Skipping dev data seeding: Restricted in non-development environments.'))
            return

        self.stdout.write('[*] Seeding development data...\n')

        # --- Organization ---
        org, created = Organization.objects.get_or_create(
            name='AVAGuard Demo',
            defaults={
                'domain_filter': 'avaguard.dev',
                'tier': 'ENTERPRISE',
                'max_users': 50,
                'is_active': True,
            }
        )
        self._report('Organization', org.name, created)

        # --- Users (one per role) ---
        hashed = make_password(DEFAULT_PASSWORD)
        users_spec = [
            {
                'email': 'admin@avaguard.dev',
                'first_name': 'Super', 'last_name': 'Admin',
                'role': 'SUPER_ADMIN', 'department': 'Management',
                'is_staff': True, 'is_superuser': True,
            },
            {
                'email': 'it@avaguard.dev',
                'first_name': 'IT', 'last_name': 'Administrator',
                'role': 'IT_ADMIN', 'department': 'IT Operations',
                'is_staff': False, 'is_superuser': False,
            },
            {
                'email': 'auditor@avaguard.dev',
                'first_name': 'Compliance', 'last_name': 'Auditor',
                'role': 'AUDITOR', 'department': 'Compliance',
                'is_staff': False, 'is_superuser': False,
            },
            {
                'email': 'viewer@avaguard.dev',
                'first_name': 'Report', 'last_name': 'Viewer',
                'role': 'VIEWER', 'department': 'Operations',
                'is_staff': False, 'is_superuser': False,
            },
        ]

        created_users = []
        for spec in users_spec:
            user, created = User.objects.get_or_create(
                email=spec['email'],
                defaults={
                    'first_name': spec['first_name'],
                    'last_name': spec['last_name'],
                    'role': spec['role'],
                    'department': spec['department'],
                    'organization': org,
                    'is_active': True,
                    'is_staff': spec['is_staff'],
                    'is_superuser': spec['is_superuser'],
                    'mfa_enabled': False,
                    'password': hashed,
                }
            )
            created_users.append(user)
            self._report('User', '%s (%s)' % (spec['email'], spec['role']), created)

        # Get users for uploaded_by
        it_user = User.objects.filter(email='it@avaguard.dev').first()
        admin_user = User.objects.filter(email='admin@avaguard.dev').first()

        # --- Sample Scans ---
        now = timezone.now()
        scans_spec = [
            {
                'overall_score': 87.50, 'passed_count': 14, 'failed_count': 2,
                'warning_count': 1, 'total_checks': 17,
                'uploaded_by': it_user,
                'scan_timestamp': now - timedelta(days=8),
            },
            {
                'overall_score': 65.00, 'passed_count': 10, 'failed_count': 5,
                'warning_count': 2, 'total_checks': 17,
                'uploaded_by': it_user,
                'scan_timestamp': now - timedelta(days=13),
            },
            {
                'overall_score': 92.00, 'passed_count': 16, 'failed_count': 1,
                'warning_count': 0, 'total_checks': 17,
                'uploaded_by': admin_user,
                'scan_timestamp': now - timedelta(days=3),
            },
        ]

        existing_count = ScanSummary.objects.filter(organization=org).count()
        if existing_count == 0:
            for spec in scans_spec:
                ScanSummary.objects.create(
                    id=uuid.uuid4(),
                    organization=org,
                    uploaded_by=spec['uploaded_by'],
                    overall_score=spec['overall_score'],
                    passed_count=spec['passed_count'],
                    failed_count=spec['failed_count'],
                    error_count=0,
                    warning_count=spec['warning_count'],
                    total_checks=spec['total_checks'],
                    tier='FREE',
                    environment='MOCK',
                    scope='Azure CIS Benchmark v2.0',
                    duration_seconds=12.5,
                    scan_timestamp=spec['scan_timestamp'],
                )
            self.stdout.write(self.style.SUCCESS('  [+] Created 3 sample scans'))
        else:
            self.stdout.write('  [=] Scans already exist (%d found), skipping' % existing_count)

        # --- Sample Audit Logs ---
        if AuditLog.objects.filter(organization=org).count() == 0:
            AuditLog.log('LOGIN', user=admin_user, details='Super Admin logged in', ip_address='127.0.0.1')
            AuditLog.log('SCAN_UPLOADED', user=it_user, details='IT Admin uploaded scan', ip_address='127.0.0.1')
            AuditLog.log('USER_CREATED', user=admin_user, details='Created viewer@avaguard.dev', ip_address='127.0.0.1')
            AuditLog.log('LOGIN', user=created_users[2], details='Auditor logged in', ip_address='192.168.1.50')
            AuditLog.log('LOGIN_FAILED', user=it_user, details='Failed login attempt', ip_address='10.0.0.5')
            self.stdout.write(self.style.SUCCESS('  [+] Created 5 audit log entries'))
        else:
            self.stdout.write('  [=] Audit logs already exist, skipping')

        # --- Summary ---
        self.stdout.write('')
        self.stdout.write(self.style.SUCCESS('=' * 50))
        self.stdout.write(self.style.SUCCESS('  Dev seed data loaded successfully!'))
        self.stdout.write(self.style.SUCCESS('=' * 50))
        self.stdout.write('')
        self.stdout.write('  Default accounts (password: %s):' % DEFAULT_PASSWORD)
        self.stdout.write('  +---------------------------+--------------+')
        self.stdout.write('  | Email                     | Role         |')
        self.stdout.write('  +---------------------------+--------------+')
        self.stdout.write('  | admin@avaguard.dev        | Super Admin  |')
        self.stdout.write('  | it@avaguard.dev           | IT Admin     |')
        self.stdout.write('  | auditor@avaguard.dev      | Auditor      |')
        self.stdout.write('  | viewer@avaguard.dev       | Viewer       |')
        self.stdout.write('  +---------------------------+--------------+')
        self.stdout.write('')

    def _report(self, model, name, created):
        if created:
            self.stdout.write(self.style.SUCCESS('  [+] Created %s: %s' % (model, name)))
        else:
            self.stdout.write('  [=] %s already exists: %s' % (model, name))
