"""
AVAGuard Web Portal - Database Models

Enterprise-grade models with Django auth integration.
Phase 0.5: Hardened with soft-delete, immutable audit logs, and MFA schema.
"""

import uuid
import hashlib
import logging
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone

logger = logging.getLogger(__name__)


class Organization(models.Model):
    """
    Company/tenant using AVAGuard.
    
    Each organization has its own scans, users, and compliance policies.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    domain_filter = models.CharField(
        max_length=100, 
        blank=True,
        help_text="Email domain for auto-assignment (e.g., acme.com)"
    )
    
    # Subscription info
    tier = models.CharField(
        max_length=20,
        choices=[('FREE', 'Free'), ('PREMIUM', 'Premium'), ('ENTERPRISE', 'Enterprise')],
        default='FREE'
    )
    subscription_expires = models.DateTimeField(null=True, blank=True)
    max_users = models.IntegerField(default=5)
    
    # Azure tenant integration
    azure_tenant_id = models.CharField(max_length=100, blank=True)
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name
    
    @property
    def user_count(self):
        return self.user_set.filter(is_active=True).count()


class UserManager(BaseUserManager):
    """Custom user manager for email-based authentication."""
    
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email is required')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', 'ADMIN')
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom user model with email authentication.
    
    Integrates with Django's auth system for password hashing and permissions.
    """
    ROLE_CHOICES = [
        ('SUPER_ADMIN', 'Super Administrator'),
        ('IT_ADMIN', 'IT Administrator'),
        ('AUDITOR', 'Auditor'),
        ('VIEWER', 'Viewer'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)
    
    organization = models.ForeignKey(
        Organization, 
        on_delete=models.CASCADE,
        null=True, 
        blank=True
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='VIEWER')
    
    # MFA — Enterprise Authentication (Phase 1.5)
    mfa_enabled = models.BooleanField(default=False)
    mfa_secret = models.CharField(max_length=100, blank=True)
    two_factor_method = models.CharField(
        max_length=10,
        choices=[('TOTP', 'Authenticator App'), ('EMAIL', 'Email OTP')],
        default='EMAIL',
        help_text="Primary 2FA method. TOTP is preferred; EMAIL is fallback."
    )
    two_factor_failed_attempts = models.IntegerField(default=0)
    email_otp_code = models.CharField(max_length=6, blank=True)
    email_otp_expiry = models.DateTimeField(null=True, blank=True)
    
    # Department
    department = models.CharField(max_length=100, blank=True)
    
    # Status
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)
    
    # Password management
    password_change_required = models.BooleanField(
        default=False,
        help_text="Force user to change password on next login"
    )
    password_last_changed = models.DateTimeField(
        null=True, 
        blank=True,
        help_text="Last password change timestamp for security scorecard"
    )
    
    # Account expiry & extensions
    expires_at = models.DateTimeField(
        null=True, 
        blank=True,
        help_text="Account auto-disables at this date/time"
    )
    extension_requested = models.BooleanField(default=False)
    extension_request_message = models.TextField(blank=True)
    extension_request_status = models.CharField(
        max_length=20, 
        choices=[('PENDING', 'Pending'), ('APPROVED', 'Approved'), ('DENIED', 'Denied')],
        blank=True,
        null=True
    )
    
    # First login flow
    is_first_login = models.BooleanField(default=True)
    
    # Accountability tracking
    modified_by = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='modified_users',
        help_text="Admin who last modified this user"
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(null=True, blank=True)
    
    objects = UserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        ordering = ['email']

    def __str__(self):
        return self.email
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}".strip() or self.email
    
    @property
    def security_score(self):
        """
        Calculate security score for scorecard badge.
        Returns: 'green', 'yellow', or 'red'
        
        Logic:
        - Green: 2FA ON + Password changed within 90 days
        - Yellow: 2FA ON but password old, OR 2FA OFF but password recent
        - Red: 2FA OFF + Password old, OR Account disabled
        """
        from datetime import timedelta
        
        if not self.is_active:
            return 'red'
        
        # Check password age (default to old if never set)
        password_recent = False
        if self.password_last_changed:
            password_age = timezone.now() - self.password_last_changed
            password_recent = password_age <= timedelta(days=90)
        
        if self.mfa_enabled and password_recent:
            return 'green'
        elif self.mfa_enabled or password_recent:
            return 'yellow'
        else:
            return 'red'
    
    @property
    def is_expired(self):
        """Check if account has expired."""
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False
        
    @property
    def is_nearing_expiry(self):
        """Check if account will expire within 7 days."""
        from datetime import timedelta
        if self.expires_at and not self.is_expired:
            return (self.expires_at - timezone.now()) <= timedelta(days=7)
        return False
        
    @property
    def has_unread_notifications(self):
        """Check if user has unread notifications based on role."""
        if self.role == 'SUPER_ADMIN':
            # Super Admin sees pending extension requests
            return User.objects.filter(
                extension_requested=True,
                extension_request_status='PENDING'
            ).exists()
        elif self.role == 'IT_ADMIN':
            # IT Admin sees failed login alerts
            from datetime import timedelta
            yesterday = timezone.now() - timedelta(hours=24)
            return AuditLog.objects.filter(
                action__icontains='FAIL',
                timestamp__gte=yesterday
            ).exists()
        return False

    def delete(self, *args, **kwargs):
        """
        Soft-delete: deactivate the user instead of removing the row.
        Preserves referential integrity and audit trails.
        """
        if kwargs.pop('hard_delete', False):
            # Escape hatch for migrations/data cleanup only
            super().delete(*args, **kwargs)
            return
        self.is_active = False
        self.save(update_fields=['is_active', 'updated_at'])
        logger.info(f"User {self.email} soft-deleted (is_active=False)")


class ScanSummary(models.Model):
    """
    Summary of a compliance scan uploaded from desktop.
    
    Acts as the parent record for individual check results.
    """
    id = models.UUIDField(primary_key=True, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    uploaded_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True,
        related_name='uploaded_scans'
    )
    
    # Score data
    overall_score = models.DecimalField(max_digits=5, decimal_places=2)
    passed_count = models.IntegerField(default=0)
    failed_count = models.IntegerField(default=0)
    error_count = models.IntegerField(default=0)
    warning_count = models.IntegerField(default=0)
    total_checks = models.IntegerField(default=0)
    
    # Metadata
    tier = models.CharField(max_length=20, default='FREE')
    environment = models.CharField(max_length=20, default='MOCK')
    target_tenant = models.CharField(max_length=100, blank=True)
    scope = models.CharField(max_length=255, default='Azure CIS Benchmark v2.0')
    duration_seconds = models.FloatField(default=0)
    
    # Timestamps
    scan_timestamp = models.DateTimeField(default=timezone.now, help_text="When scan was run on desktop")
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-scan_timestamp']
        verbose_name_plural = "Scan Summaries"

    def __str__(self):
        return f"Scan {self.id} - {self.overall_score}%"
    
    @property
    def compliance_rate(self):
        if self.total_checks == 0:
            return 100.0
        return (self.passed_count / self.total_checks) * 100


class ScanResult(models.Model):
    """
    Individual check result within a scan.
    
    Stores detailed results for each CIS check.
    """
    STATUS_CHOICES = [
        ('PASS', 'Pass'),
        ('FAIL', 'Fail'),
        ('ERROR', 'Error'),
        ('WARNING', 'Warning'),
        ('SKIPPED', 'Skipped'),
    ]
    
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
        ('INFO', 'Informational'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(
        ScanSummary, 
        on_delete=models.CASCADE,
        related_name='results',
        null=True  # Temporary for migration
    )
    
    # Check identification
    check_id = models.CharField(max_length=20, default='')
    cis_control_id = models.CharField(max_length=50, blank=True)
    title = models.CharField(max_length=500, default='')
    category = models.CharField(max_length=100, blank=True)
    
    # Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='FAIL')
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='MEDIUM')
    
    # Counts
    compliant_count = models.IntegerField(default=0)
    non_compliant_count = models.IntegerField(default=0)
    total_count = models.IntegerField(default=0)
    compliance_percentage = models.FloatField(default=0)
    
    # Details
    details = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    error_message = models.TextField(blank=True)
    
    # Metadata
    evidence = models.JSONField(default=dict, blank=True)
    non_compliant_resources = models.JSONField(default=list, blank=True)
    
    # Timing
    duration_seconds = models.FloatField(default=0)
    
    class Meta:
        ordering = ['check_id']
        unique_together = ['scan', 'check_id']

    def __str__(self):
        return f"{self.check_id}: {self.status}"


class CompliancePolicy(models.Model):
    """
    Custom compliance policy/configuration for an organization.
    
    Allows organizations to customize check behavior.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    
    # Check configuration
    check_id = models.CharField(max_length=20)
    is_enabled = models.BooleanField(default=True)
    severity_override = models.CharField(
        max_length=20, 
        choices=ScanResult.SEVERITY_CHOICES,
        blank=True
    )
    
    # Exemptions
    exempt_resources = models.JSONField(
        default=list, 
        blank=True,
        help_text="List of resource IDs exempt from this check"
    )
    exemption_reason = models.TextField(blank=True)
    exemption_expires = models.DateTimeField(null=True, blank=True)
    
    # Audit
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['check_id']
        unique_together = ['organization', 'check_id']
        verbose_name_plural = "Compliance Policies"

    def __str__(self):
        return f"{self.organization.name} - {self.check_id}"


class AuditLog(models.Model):
    """
    Comprehensive audit log for all user actions (SRS FR-29).
    
    Tracks all significant operations for compliance purposes.
    """
    ACTION_CHOICES = [
        ('LOGIN', 'User Login'),
        ('LOGOUT', 'User Logout'),
        ('LOGIN_FAILED', 'Failed Login'),
        ('SCAN_UPLOADED', 'Scan Uploaded'),
        ('REPORT_VIEWED', 'Report Viewed'),
        ('REPORT_EXPORTED', 'Report Exported'),
        ('USER_CREATED', 'User Created'),
        ('USER_UPDATED', 'User Updated'),
        ('USER_DELETED', 'User Deleted'),
        ('POLICY_CREATED', 'Policy Created'),
        ('POLICY_UPDATED', 'Policy Updated'),
        ('MFA_ENABLED', 'MFA Enabled'),
        ('MFA_DISABLED', 'MFA Disabled'),
        ('PASSWORD_CHANGED', 'Password Changed'),
        ('API_KEY_CREATED', 'API Key Created'),
        # New actions for tethered security
        ('OTP_SENT', 'OTP Sent'),
        ('OTP_VERIFIED', 'OTP Verified'),
        ('OTP_FAILED', 'OTP Verification Failed'),
        ('DEVICE_REGISTERED', 'Device Registered'),
        ('DEVICE_AUTHORIZED', 'Device Authorized'),
        ('DEVICE_REVOKED', 'Device Revoked'),
        ('SESSION_REVOKED', 'Session Revoked'),
        ('HEARTBEAT', 'Desktop Heartbeat'),
        # New actions for advanced user management
        ('2FA_ENABLED', '2FA Enabled'),
        ('2FA_DISABLED', '2FA Disabled'),
        ('ACCOUNT_ACTIVATED', 'Account Activated'),
        ('ACCOUNT_DEACTIVATED', 'Account Deactivated'),
        ('PASSWORD_RESET_FORCED', 'Password Reset Forced'),
        ('BULK_ACTION', 'Bulk Action'),
        ('ACCOUNT_EXPIRY_SET', 'Account Expiry Set'),
    ]
    # Sudo-mode and MFA lifecycle actions
    SUDO_ACTIONS = [
        ('SUDO_CONFIRMED', 'Sudo Mode Confirmed'),
        ('MFA_RESET_BY_ADMIN', 'MFA Reset By Admin'),
        ('TOTP_PROVISIONED', 'TOTP Provisioned'),
    ]
    ACTION_CHOICES += SUDO_ACTIONS
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization, 
        on_delete=models.CASCADE,
        null=True
    )
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    details = models.TextField(blank=True)
    
    # Request context
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=500, blank=True)
    
    # Related objects
    related_object_type = models.CharField(max_length=100, blank=True)
    related_object_id = models.CharField(max_length=100, blank=True)
    
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # Integrity — hash chain for tamper detection
    integrity_hash = models.CharField(
        max_length=64, blank=True,
        help_text="SHA-256 hash of this entry chained to the previous entry."
    )
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['organization', 'timestamp']),
            models.Index(fields=['user', 'action']),
            models.Index(fields=['timestamp', 'id']),  # Keyset pagination
        ]

    def __str__(self):
        return f"{self.action} by {self.user} at {self.timestamp}"

    def save(self, *args, **kwargs):
        """
        Immutable audit log: only INSERT is allowed.
        Updates to existing entries are blocked to prevent tampering.
        """
        if self.pk and AuditLog.objects.filter(pk=self.pk).exists():
            raise ValueError(
                "AuditLog entries are immutable. "
                "Updates are not permitted for compliance integrity."
            )
        # Compute integrity hash before first save
        if not self.integrity_hash:
            self.integrity_hash = self._compute_hash()
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """
        Block deletion of audit log entries.
        Audit logs must be preserved for compliance and forensic analysis.
        """
        raise ValueError(
            "AuditLog entries cannot be deleted. "
            "This is enforced for compliance and tamper resistance."
        )

    def _compute_hash(self):
        """Compute SHA-256 hash chaining this entry to the previous one."""
        # Get the hash of the most recent entry (chain link)
        previous_hash = ''
        last_entry = AuditLog.objects.order_by('-timestamp').values_list(
            'integrity_hash', flat=True
        ).first()
        if last_entry:
            previous_hash = last_entry

        payload = (
            f"{previous_hash}|"
            f"{self.action}|"
            f"{self.user_id or ''}|"
            f"{self.details}|"
            f"{self.ip_address or ''}"
        )
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()

    @classmethod
    def log(cls, action, user=None, organization=None, details='', 
            ip_address=None, user_agent='', related_object=None):
        """Create an immutable audit log entry with integrity hash."""
        entry = cls(
            action=action,
            user=user,
            organization=organization or (user.organization if user else None),
            details=details,
            ip_address=ip_address,
            user_agent=user_agent[:500] if user_agent else '',
        )
        
        if related_object:
            entry.related_object_type = related_object.__class__.__name__
            entry.related_object_id = str(related_object.pk)
        
        entry.save()
        return entry
    
    @classmethod
    def archive_old_logs(cls, days=90):
        """
        Archive audit logs older than specified days.
        Does NOT delete — marks them as archived.
        
        Args:
            days: Log age threshold (default 90 days)
            
        Returns:
            int: Number of old log entries found for archival.
        """
        from datetime import timedelta
        cutoff_time = timezone.now() - timedelta(days=days)
        return cls.objects.filter(timestamp__lt=cutoff_time).count()


class DeviceAuthorization(models.Model):
    """
    Tracks device authorization tokens for desktop-web handshake.
    
    The desktop app generates a token, polls for approval, and the web
    browser (on same device) approves it.
    """
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('APPROVED', 'Approved'),
        ('EXPIRED', 'Expired'),
        ('REVOKED', 'Revoked'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device_token = models.CharField(max_length=64, unique=True, db_index=True)
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        null=True, 
        blank=True,
        related_name='device_authorizations'
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    device_name = models.CharField(max_length=255, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()  # Token expires in 5 mins if not approved
    last_heartbeat = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Device {self.device_token[:8]}... - {self.status}"
    
    @property
    def is_expired(self):
        """Check if token has expired."""
        return timezone.now() > self.expires_at
    
    @property
    def is_valid(self):
        """Check if token is valid for use."""
        return self.status == 'APPROVED' and not self.is_expired


class OTPVerification(models.Model):
    """
    Stores 6-digit OTP codes for 2FA.
    
    Codes are valid for 60 seconds and single-use.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='otp_codes')
    code = models.CharField(max_length=6)
    
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()  # 60 seconds from creation
    is_used = models.BooleanField(default=False)
    
    # Session tracking for multi-step login
    session_id = models.CharField(max_length=64, db_index=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"OTP for {self.user.email} - {'Used' if self.is_used else 'Active'}"
    
    @property
    def is_expired(self):
        """Check if OTP has expired."""
        return timezone.now() > self.expires_at
    
    @property
    def is_valid(self):
        """Check if OTP is still usable."""
        return not self.is_used and not self.is_expired


class ActiveSession(models.Model):
    """
    Tracks active desktop sessions for admin monitoring and revocation.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='active_sessions')
    device_auth = models.ForeignKey(
        DeviceAuthorization, 
        on_delete=models.CASCADE,
        related_name='sessions'
    )
    
    # JWT tracking for revocation
    jwt_jti = models.CharField(max_length=64, unique=True, db_index=True)
    
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=500, blank=True)
    
    started_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['-started_at']
        verbose_name_plural = 'Active Sessions'
    
    def __str__(self):
        status = 'Active' if self.is_active else 'Revoked'
        return f"{self.user.email} - {status} - {self.started_at.strftime('%Y-%m-%d %H:%M')}"

    @property
    def is_stale(self):
        """
        Returns True if the desktop agent has not sent a heartbeat
        in the last 30 minutes, indicating a possible disconnection.
        """
        from datetime import timedelta
        return timezone.now() - self.last_activity > timedelta(minutes=30)

    def revoke(self):
        """Revoke this session."""
        self.is_active = False
        self.save()
        # Also revoke the device authorization
        if self.device_auth:
            self.device_auth.status = 'REVOKED'
            self.device_auth.save()
    
    @classmethod
    def cleanup_expired(cls, max_age_hours=24):
        """
        Revoke all sessions older than max_age_hours.
        
        Args:
            max_age_hours: Maximum session age in hours (default 24)
            
        Returns:
            int: Number of sessions revoked
        """
        from datetime import timedelta
        
        cutoff_time = timezone.now() - timedelta(hours=max_age_hours)
        expired_sessions = cls.objects.filter(
            is_active=True,
            started_at__lt=cutoff_time
        )
        
        count = 0
        for session in expired_sessions:
            session.revoke()
            count += 1
        
        return count

    @classmethod
    def cleanup_stale(cls, stale_minutes=30):
        """
        Revoke sessions where the desktop agent has stopped sending heartbeats.
        A session is considered stale when last_activity exceeds stale_minutes.
        
        Args:
            stale_minutes: Minutes since last heartbeat before marking stale (default 30)
            
        Returns:
            int: Number of sessions marked stale
        """
        from datetime import timedelta
        
        cutoff_time = timezone.now() - timedelta(minutes=stale_minutes)
        stale_sessions = cls.objects.filter(
            is_active=True,
            last_activity__lt=cutoff_time
        )
        
        count = 0
        for session in stale_sessions:
            session.is_active = False
            session.save(update_fields=['is_active'])
            count += 1
            
        return count


class Notification(models.Model):
    """
    Persistent notifications for administrators (e.g., account extension requests).
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    title = models.CharField(max_length=255)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    # Link to related object
    related_user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='+')
    action_url = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"To {self.recipient.email}: {self.title}"






class APIUsageLog(models.Model):
    endpoint = models.CharField(max_length=255)
    calls = models.IntegerField(default=0)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']


class Policy(models.Model):
    """
    Security policies enforced by AVAGuard desktop agents.

    Each policy maps to one or more compliance framework controls (CIS, HIPAA,
    SOC2, PCI-DSS, ISO 27001) and has a severity classification. Policies can
    be enabled, disabled, or set as organization-level overrides.
    """
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH',     'High'),
        ('MEDIUM',   'Medium'),
        ('LOW',      'Low'),
        ('INFO',     'Informational'),
    ]

    FRAMEWORK_CHOICES = [
        ('CIS',     'CIS Benchmarks'),
        ('HIPAA',   'HIPAA'),
        ('SOC2',    'SOC 2'),
        ('PCI',     'PCI DSS'),
        ('ISO27001', 'ISO 27001'),
        ('NIST',    'NIST CSF'),
        ('CUSTOM',  'Custom'),
    ]

    CATEGORY_CHOICES = [
        ('Authentication',    'Authentication'),
        ('Network',           'Network Security'),
        ('Data Protection',   'Data Protection'),
        ('Endpoint Security', 'Endpoint Security'),
        ('System',            'System Configuration'),
        ('Logging',           'Logging & Auditing'),
        ('Access Control',    'Access Control'),
        ('Encryption',        'Encryption'),
        ('Custom',            'Custom'),
    ]

    STATUS_CHOICES = [
        ('ACTIVE',    'Active'),
        ('DISABLED',  'Disabled'),
        ('DRAFT',     'Draft'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='policies',
        null=True,
        blank=True,
        help_text="Null = global policy applicable to all organizations"
    )

    # Core fields
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, default='System')
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='MEDIUM')
    framework = models.CharField(max_length=20, choices=FRAMEWORK_CHOICES, default='CIS')
    control_id = models.CharField(
        max_length=50,
        blank=True,
        help_text="Framework control reference (e.g., CIS 1.1.1, HIPAA §164.312)"
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='ACTIVE')

    # Enforcement settings
    check_id = models.CharField(
        max_length=100,
        blank=True,
        help_text="Links to an AVAILABLE_CHECKS key in the desktop agent engine"
    )
    remediation_guidance = models.TextField(blank=True)
    is_custom = models.BooleanField(default=False, help_text="True if created by the organization")

    # Audit trail
    created_by = models.ForeignKey(
        'User', on_delete=models.SET_NULL, null=True, blank=True, related_name='policies_created'
    )
    modified_by = models.ForeignKey(
        'User', on_delete=models.SET_NULL, null=True, blank=True, related_name='policies_modified'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['category', 'severity', 'name']
        verbose_name_plural = 'Policies'

    def __str__(self):
        return f"[{self.severity}] {self.name} ({self.framework})"

    @property
    def is_active(self):
        return self.status == 'ACTIVE'

    def enable(self, user=None):
        self.status = 'ACTIVE'
        self.modified_by = user
        self.save(update_fields=['status', 'modified_by', 'updated_at'])

    def disable(self, user=None):
        self.status = 'DISABLED'
        self.modified_by = user
        self.save(update_fields=['status', 'modified_by', 'updated_at'])
