import json
import uuid
import random
import os
from datetime import datetime
from django.core.management.base import BaseCommand
from django.utils import timezone
from core.models import Organization, User, ScanSummary, ScanResult, AuditLog
from django.contrib.auth.hashers import make_password

class Command(BaseCommand):
    help = 'Ingests enterprise_dataset.json into the database for high-fidelity dashboard testing'

    def add_arguments(self, parser):
        parser.add_argument('--file', type=str, default='mock_output/enterprise_dataset.json', help='Path to the mock dataset JSON')
        parser.add_argument('--org', type=str, default='AgencyVA', help='Organization name')
        parser.add_argument('--clean', action='store_true', help='Clean existing data before ingestion')

    def handle(self, *args, **options):
        file_path = options['file']
        org_name = options['org']
        clean = options['clean']

        if not os.path.exists(file_path):
            self.stdout.write(self.style.ERROR(f"File not found: {file_path}"))
            return

        self.stdout.write(f"[*] Reading {file_path}...")
        with open(file_path, 'r') as f:
            data = json.load(f)

        self.stdout.write(f"[*] Data loaded. Processing {len(data.get('users', []))} users and {len(data.get('scans', []))} scans...")

        # 1. Organization
        org, _ = Organization.objects.get_or_create(
            name=org_name,
            defaults={'domain_filter': 'agencyva.com', 'tier': 'ENTERPRISE', 'is_active': True}
        )

        if clean:
            self.stdout.write("[*] Cleaning existing data for this org...")
            ScanSummary.objects.filter(organization=org).delete()
            User.objects.filter(organization=org).exclude(is_superuser=True).delete()
            AuditLog.objects.filter(organization=org).delete()

        # 2. Users
        password = make_password('AgencyVA123!')
        user_map = {}
        users_to_create = []
        
        existing_emails = set(User.objects.values_list('email', flat=True))
        
        for u_data in data.get('users', []):
            if u_data['mail'] in existing_emails:
                user_map[u_data['id']] = User.objects.get(email=u_data['mail'])
                continue
                
            hire_date = datetime.strptime(u_data['hireDate'], '%Y-%m-%d')
            # Fix for timezone-aware datetime if needed
            hire_date = timezone.make_aware(hire_date) if timezone.is_naive(hire_date) else hire_date
            
            user = User(
                email=u_data['mail'],
                first_name=u_data['givenName'],
                last_name=u_data['surname'],
                role='VIEWER',
                department=u_data['department'],
                organization=org,
                is_active=True,
                password=password,
                mfa_enabled=u_data['isMfaRegistered'],
            )
            users_to_create.append(user)
            user_map[u_data['id']] = user

        if users_to_create:
            User.objects.bulk_create(users_to_create)
            # Re-fetch to get IDs
            for u in User.objects.filter(organization=org):
                # This is a bit slow but works for mapping
                for mock_id, user_obj in user_map.items():
                    if user_obj.email == u.email:
                        user_map[mock_id] = u

        # 3. Scans
        self.stdout.write("[*] Ingesting scans...")
        for s_data in data.get('scans', []):
            scan_id = uuid.UUID(s_data['scanId']) if 'scanId' in s_data else uuid.uuid4()
            
            u_id = s_data.get('userId')
            uploaded_by = user_map.get(u_id) if u_id else random.choice(list(user_map.values()))

            scan_ts = datetime.strptime(s_data['scanDate'], '%Y-%m-%dT%H:%M:%SZ')
            scan_ts = timezone.make_aware(scan_ts) if timezone.is_naive(scan_ts) else scan_ts

            scan_summary = ScanSummary.objects.create(
                id=scan_id,
                organization=org,
                uploaded_by=uploaded_by,
                overall_score=s_data['complianceScore'],
                passed_count=s_data['summary']['passed'],
                failed_count=s_data['summary']['failed'],
                warning_count=s_data['summary']['warnings'],
                total_checks=s_data['summary']['total'],
                environment=s_data.get('device', {}).get('osType', 'MOCK'),
                scope=s_data.get('profile', 'Azure CIS Benchmark v2.0'),
                scan_timestamp=scan_ts
            )

            # Add individual results (Top 20 only to keep DB size sane)
            results_to_create = []
            for r_data in s_data.get('checks', [])[:20]:
                results_to_create.append(ScanResult(
                    scan=scan_summary,
                    check_id=r_data['checkId'],
                    title=r_data['title'],
                    status=r_data['result'],
                    severity=r_data['severity'],
                    category=r_data['frameworks'][0] if r_data['frameworks'] else 'General'
                ))
            ScanResult.objects.bulk_create(results_to_create)

        # 4. Audit Logs
        self.stdout.write("[*] Ingesting audit logs...")
        logs_to_create = []
        for l_data in data.get('audit', {}).get('signInLogs', []):
            user = User.objects.filter(email=l_data['userPrincipalName']).first()
            if not user: continue
            
            ts = datetime.strptime(l_data['createdDateTime'], '%Y-%m-%dT%H:%M:%SZ')
            ts = timezone.make_aware(ts) if timezone.is_naive(ts) else ts
            
            logs_to_create.append(AuditLog(
                organization=org,
                user=user,
                action='LOGIN' if l_data['status']['errorCode'] == 0 else 'LOGIN_FAILED',
                details=f"Sign-in to {l_data['appDisplayName']}",
                ip_address=l_data['ipAddress'],
                timestamp=ts
            ))
        
        if logs_to_create:
            # AuditLog.save() has a custom immutable check, so bulk_create might bypass it or fail if not careful.
            # But since these are NEW entries (no pk yet), it should be fine.
            AuditLog.objects.bulk_create(logs_to_create)

        self.stdout.write(self.style.SUCCESS(f"Successfully ingested mock data for {org_name}"))
