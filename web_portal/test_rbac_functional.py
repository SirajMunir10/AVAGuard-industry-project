import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from django.test import Client
from core.models import User

# Define the pages to test per role
# Assuming default organization exists or we bypass it
urls_to_test = {
    'SUPER_ADMIN': [
        '/dashboard/', '/system/users/', '/system/sessions/', '/system/audit-logs/', '/scans/', '/reports/', '/settings/', '/settings/organization/'
    ],
    'IT_ADMIN': [
        '/dashboard/', '/system/sessions/', '/scans/', '/reports/'
    ],
    'AUDITOR': [
        '/dashboard/', '/scans/', '/reports/', '/settings/'
    ],
    'VIEWER': [
        '/dashboard/', '/scans/', '/reports/', '/settings/'
    ]
}

client = Client(HTTP_HOST='localhost')

print("--- Functional Route Testing ---")
for role, urls in urls_to_test.items():
    print(f"\nTesting role: {role}")
    
    # Get or create user
    email = f"test_{role.lower()}@avaguard.local"
    user, created = User.objects.get_or_create(
        email=email,
        defaults={'first_name': role, 'last_name': 'Test', 'role': role}
    )
    if created:
        user.set_password('testpassword123')
        user.save()
        
    # Set password change not required
    user.password_change_required = False
    user.is_first_login = False
    user.mfa_enabled = True # bypass MFA setup
    user.save()
    
    # Login
    client.force_login(user)
    
    for url in urls:
        try:
            response = client.get(url, follow=True)
            status = response.status_code
            print(f"[{status}] {url}")
            if status >= 400 and status != 403:
                print(f"  ERROR: Unexpected status code {status} for {url}")
        except Exception as e:
            print(f"  EXCEPTION: {url} -> {str(e)}")
    
    client.logout()

print("\n--- Testing RBAC Sessions Revocation View Context ---")
# Create Super Admin B
sa_b, _ = User.objects.get_or_create(email="sa_b@avaguard.local", defaults={'role': 'SUPER_ADMIN', 'password_change_required': False, 'is_first_login': False, 'mfa_enabled': True})
it_a, _ = User.objects.get_or_create(email="it_a@avaguard.local", defaults={'role': 'IT_ADMIN', 'password_change_required': False, 'is_first_login': False, 'mfa_enabled': True})

from core.models import ActiveSession, DeviceAuthorization
import uuid

from django.utils import timezone
from datetime import timedelta

now = timezone.now()
sa_b_device, _ = DeviceAuthorization.objects.get_or_create(device_token='token1', defaults={'id': uuid.uuid4(), 'user': sa_b, 'device_name': 'SA B Device', 'expires_at': now + timedelta(days=30)})
it_a_device, _ = DeviceAuthorization.objects.get_or_create(device_token='token2', defaults={'id': uuid.uuid4(), 'user': it_a, 'device_name': 'IT A Device', 'expires_at': now + timedelta(days=30)})

sa_b_session, _ = ActiveSession.objects.get_or_create(jwt_jti='jti1', defaults={'id': uuid.uuid4(), 'user': sa_b, 'device_auth': sa_b_device, 'ip_address': '127.0.0.1', 'is_active': True})
it_a_session, _ = ActiveSession.objects.get_or_create(jwt_jti='jti2', defaults={'id': uuid.uuid4(), 'user': it_a, 'device_auth': it_a_device, 'ip_address': '127.0.0.1', 'is_active': True})

# Test as Super Admin A
sa_a = User.objects.get(email="test_super_admin@avaguard.local")
client.force_login(sa_a)
resp = client.get('/system/sessions/')
print(f"Super Admin A accessing sessions page status: {resp.status_code}")
if resp.status_code == 302:
    print(f"Redirecting to: {resp.url}")
if getattr(resp, 'context', None):
    for session in resp.context['sessions']:
        if session.user.email == "sa_b@avaguard.local":
            print(f"Super Admin A can revoke Super Admin B: {session.can_revoke}")
        elif session.user.email == sa_a.email:
            print(f"Super Admin A can revoke self: {session.can_revoke}")
client.logout()

# Test as IT Admin
it_a_user = User.objects.get(email="test_it_admin@avaguard.local")
client.force_login(it_a_user)
resp = client.get('/system/sessions/')
if 'sessions' in resp.context:
    for session in resp.context['sessions']:
        if session.user.email == "it_a@avaguard.local": # another IT admin
            print(f"IT Admin can revoke another IT Admin: {session.can_revoke}")
        elif session.user.email == "sa_b@avaguard.local":
            print(f"IT Admin can revoke Super Admin B: {session.can_revoke}")
        elif session.user.email == it_a_user.email:
            print(f"IT Admin can revoke self: {session.can_revoke}")
client.logout()

# Test as Auditor
auditor = User.objects.get(email="test_auditor@avaguard.local")
client.force_login(auditor)
resp = client.get('/system/sessions/')
print(f"Auditor accessing sessions page status: {resp.status_code} (Expect 302/redirect because of admin_required)")
client.logout()

# Test as Viewer
viewer = User.objects.get(email="test_viewer@avaguard.local")
client.force_login(viewer)
resp = client.get('/system/sessions/')
print(f"Viewer accessing sessions page status: {resp.status_code} (Expect 302/redirect because of admin_required)")

print("\nDone.")
