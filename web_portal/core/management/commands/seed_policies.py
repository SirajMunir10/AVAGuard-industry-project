from django.core.management.base import BaseCommand
from core.models import Policy, Organization

class Command(BaseCommand):
    help = 'Seeds the database with default compliance policies'

    def handle(self, *args, **kwargs):
        # We'll seed them as global policies (organization=None)
        default_policies = [
            {
                'name': 'Password Complexity Requirements',
                'description': 'Ensure passwords meet minimum complexity: 12 chars, upper, lower, number, special.',
                'category': 'Authentication',
                'severity': 'CRITICAL',
                'framework': 'CIS',
                'status': 'ACTIVE',
            },
            {
                'name': 'Firewall Configuration Check',
                'description': 'Ensure OS firewall is active and blocking inbound connections by default.',
                'category': 'Network',
                'severity': 'CRITICAL',
                'framework': 'CIS',
                'status': 'ACTIVE',
            },
            {
                'name': 'Disk Encryption Status',
                'description': 'Ensure full disk encryption (BitLocker/FileVault) is enabled on all volumes.',
                'category': 'Data Protection',
                'severity': 'HIGH',
                'framework': 'SOC2',
                'status': 'ACTIVE',
            },
            {
                'name': 'Antivirus Real-time Protection',
                'description': 'Verify real-time protection is enabled in Windows Defender or equivalent.',
                'category': 'Endpoint Security',
                'severity': 'HIGH',
                'framework': 'HIPAA',
                'status': 'ACTIVE',
            },
            {
                'name': 'Software Update Status',
                'description': 'Ensure automatic OS updates are enabled and no critical patches are missing.',
                'category': 'System',
                'severity': 'MEDIUM',
                'framework': 'ISO27001',
                'status': 'DISABLED',
            }
        ]

        created_count = 0
        for p_data in default_policies:
            obj, created = Policy.objects.get_or_create(
                name=p_data['name'],
                organization=None, # Global
                defaults={
                    'description': p_data['description'],
                    'category': p_data['category'],
                    'severity': p_data['severity'],
                    'framework': p_data['framework'],
                    'status': p_data['status'],
                    'is_custom': False
                }
            )
            if created:
                created_count += 1

        self.stdout.write(self.style.SUCCESS(f'Successfully seeded {created_count} default policies.'))
