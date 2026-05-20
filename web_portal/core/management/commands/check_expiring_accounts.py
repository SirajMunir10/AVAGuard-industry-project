import logging
from datetime import timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from core.models import User, Notification

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Checks for expiring accounts and sends notifications'

    def handle(self, *args, **options):
        now = timezone.now()
        warning_threshold = now + timedelta(days=7)
        
        # 1. Check for accounts expiring within 7 days that haven't requested an extension
        expiring_users = User.objects.filter(
            is_active=True,
            expires_at__isnull=False,
            expires_at__gt=now,
            expires_at__lte=warning_threshold,
            extension_requested=False
        )
        
        for user in expiring_users:
            self.stdout.write(self.style.WARNING(f"User {user.email} is nearing expiry on {user.expires_at}"))
            
            # Send warning email
            send_mail(
                subject='AVAGuard - Account Expiry Warning',
                message=f'Hello {user.first_name or user.email},\n\nYour account is scheduled to expire on {user.expires_at.strftime("%Y-%m-%d")}. Please log in to your dashboard to request an extension if you still require access.',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=True,
            )
            
        # 2. Check for accounts that have passed their expiry date but are still active
        # The login middleware blocks access, but we should also deactivate them to be safe
        expired_users = User.objects.filter(
            is_active=True,
            expires_at__isnull=False,
            expires_at__lte=now
        )
        
        for user in expired_users:
            self.stdout.write(self.style.ERROR(f"User {user.email} has expired. Deactivating."))
            user.is_active = False
            user.save(update_fields=['is_active'])
            
            # Send expiration email
            send_mail(
                subject='AVAGuard - Account Expired',
                message=f'Hello {user.first_name or user.email},\n\nYour account has expired as of {user.expires_at.strftime("%Y-%m-%d")}. If you require access, please contact your administrator or request an extension from the login portal.',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=True,
            )
            
            # Notify super admins
            admin_users = User.objects.filter(role__in=['SUPER_ADMIN', 'IT_ADMIN'], is_active=True)
            notifications = []
            for admin in admin_users:
                notifications.append(Notification(
                    recipient=admin,
                    title="Account Expired",
                    message=f"User {user.email} account has expired and been automatically deactivated.",
                    related_user=user,
                    action_url="/system/users/"
                ))
            if notifications:
                Notification.objects.bulk_create(notifications)
                
        self.stdout.write(self.style.SUCCESS(f'Successfully processed expiry checks. Expiring: {expiring_users.count()}, Expired: {expired_users.count()}'))
