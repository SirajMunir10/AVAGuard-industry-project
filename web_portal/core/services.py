"""
AVAGuard Web Portal - Security Services

Business logic for OTP generation, device authorization, and session management.
"""

import random
import string
import secrets
import logging
from datetime import timedelta
from typing import Optional, Tuple

from django.utils import timezone
from django.conf import settings

from core.models import User, OTPVerification, DeviceAuthorization, ActiveSession, AuditLog

logger = logging.getLogger(__name__)


class OTPService:
    """
    Service for generating, sending, and verifying OTP codes.
    
    For development: OTP codes are printed to console.
    For production: Would integrate with email/SMS provider.
    """
    
    OTP_LENGTH = 6
    OTP_EXPIRY_SECONDS = 60  # 60 seconds validity
    
    @classmethod
    def generate_otp(cls, user: User, session_id: str) -> str:
        """
        Generate a new 6-digit OTP code for the user.
        
        Args:
            user: The user to generate OTP for
            session_id: Unique session ID to track the login attempt
            
        Returns:
            The generated 6-digit code
        """
        # Generate 6-digit numeric code
        code = ''.join(random.choices(string.digits, k=cls.OTP_LENGTH))
        
        # Calculate expiry time
        expires_at = timezone.now() + timedelta(seconds=cls.OTP_EXPIRY_SECONDS)
        
        # Invalidate any existing unused OTPs for this user
        OTPVerification.objects.filter(
            user=user,
            is_used=False
        ).update(is_used=True)
        
        # Create new OTP record
        otp = OTPVerification.objects.create(
            user=user,
            code=code,
            session_id=session_id,
            expires_at=expires_at
        )
        
        logger.info(f"OTP generated for user {user.email}, session {session_id[:8]}...")
        
        return code
    
    @classmethod
    def send_otp(cls, user: User, code: str) -> bool:
        """
        Send OTP to user via email.
        
        Uses Gmail SMTP configured in settings.py.
        Falls back to console output if email fails.
        """
        from django.core.mail import send_mail, EmailMultiAlternatives
        from django.template.loader import render_to_string
        from django.conf import settings
        import sys
        
        subject = '🔐 AVAGuard Security - Your Verification Code'
        
        # Plain text version
        text_content = f"""
AVAGuard Security Verification

Your verification code is: {code}

This code will expire in {cls.OTP_EXPIRY_SECONDS} seconds.

If you did not request this code, please ignore this email and ensure your account is secure.

— AVAGuard Security Team
        """
        
        # HTML version
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #0f0f23; color: #ffffff; padding: 40px; }}
        .container {{ max-width: 500px; margin: 0 auto; background: #1a1a2e; border-radius: 16px; padding: 40px; border: 1px solid #2a2a4a; }}
        .logo {{ font-size: 24px; font-weight: bold; color: #00d4ff; margin-bottom: 24px; }}
        .code-box {{ background: linear-gradient(135deg, #00d4ff22, #00ff8822); border: 2px solid #00d4ff; border-radius: 12px; padding: 24px; text-align: center; margin: 24px 0; }}
        .code {{ font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #00d4ff; font-family: monospace; }}
        .expiry {{ color: #ffd93d; font-size: 14px; margin-top: 16px; }}
        .warning {{ background: #ff6b6b22; border-left: 4px solid #ff6b6b; padding: 12px 16px; margin-top: 24px; font-size: 13px; color: #ff9999; }}
        .footer {{ margin-top: 32px; font-size: 12px; color: #666; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🛡️ AVAGuard Security</div>
        <p>Hello <strong>{user.first_name or user.email}</strong>,</p>
        <p>You requested a verification code to access AVAGuard. Enter this code to continue:</p>
        <div class="code-box">
            <div class="code">{code}</div>
            <div class="expiry">⏱️ Expires in {cls.OTP_EXPIRY_SECONDS} seconds</div>
        </div>
        <div class="warning">
            ⚠️ <strong>Security Notice:</strong> Never share this code with anyone. AVAGuard will never ask for your verification code.
        </div>
        <div class="footer">
            This is an automated message from AVAGuard Security.<br>
            © 2025 AVAGuard
        </div>
    </div>
</body>
</html>
        """
        
        try:
            # Try sending email
            email = EmailMultiAlternatives(
                subject=subject,
                body=text_content,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[user.email]
            )
            email.attach_alternative(html_content, "text/html")
            email.send(fail_silently=False)
            
            logger.info(f"✅ OTP email sent successfully to {user.email}")
            
            # Also print to console for debugging
            print(f"\n📧 OTP Email sent to: {user.email}")
            print(f"   Code: {code} (expires in {cls.OTP_EXPIRY_SECONDS}s)\n")
            
        except Exception as e:
            # Fallback to console if email fails
            logger.error(f"❌ Email failed: {e}. Falling back to console.")
            
            msg = (
                "\n" + "=" * 60 + "\n"
                "🔐 AVAGuard 2FA Verification Code (EMAIL FAILED)\n"
                "=" * 60 + "\n"
                f"   User: {user.email}\n"
                f"   Code: {code}\n"
                f"   Valid for: {cls.OTP_EXPIRY_SECONDS} seconds\n"
                f"   Error: {str(e)[:50]}\n"
                "=" * 60 + "\n\n"
            )
            sys.stdout.write(msg)
            sys.stdout.flush()
        
        # Log the action
        AuditLog.log(
            action='OTP_SENT',
            user=user,
            details=f"OTP sent to {user.email}"
        )
        
        return True






    @classmethod
    def verify_otp(cls, user: User, code: str, session_id: str) -> Tuple[bool, str]:
        """
        Verify an OTP code.
        
        Args:
            user: The user attempting verification
            code: The OTP code entered by user
            session_id: The session ID from the login attempt
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            otp = OTPVerification.objects.get(
                user=user,
                session_id=session_id,
                is_used=False
            )
        except OTPVerification.DoesNotExist:
            AuditLog.log(
                action='OTP_FAILED',
                user=user,
                details="No valid OTP found for session"
            )
            return False, "Invalid or expired code. Please request a new one."
        
        # Check if expired
        if otp.is_expired:
            AuditLog.log(
                action='OTP_FAILED',
                user=user,
                details="OTP expired"
            )
            return False, "Code has expired. Please request a new one."
        
        # Check if code matches
        if otp.code != code:
            AuditLog.log(
                action='OTP_FAILED',
                user=user,
                details="Incorrect OTP code entered"
            )
            return False, "Incorrect code. Please try again."
        
        # Mark as used
        otp.is_used = True
        otp.save()
        
        AuditLog.log(
            action='OTP_VERIFIED',
            user=user,
            details="2FA verification successful"
        )
        
        logger.info(f"OTP verified successfully for {user.email}")
        return True, "Verification successful"
    
    @classmethod
    def generate_session_id(cls) -> str:
        """Generate a unique session ID for login tracking."""
        return secrets.token_urlsafe(32)


class DeviceAuthService:
    """
    Service for device authorization handshake.
    
    Flow:
    1. Desktop generates token and registers with web API
    2. Desktop opens browser with token in URL
    3. User logs in to web portal
    4. User approves device on authorization page
    5. Desktop (polling) receives approval and JWT
    """
    
    TOKEN_EXPIRY_MINUTES = 5  # Token expires in 5 minutes if not approved
    
    @classmethod
    def generate_device_token(cls) -> str:
        """
        Generate a secure random device token.
        
        Format: auth_{random_12_chars}_{random_8_chars}
        """
        prefix = "auth"
        part1 = secrets.token_hex(6)  # 12 hex chars
        part2 = secrets.token_hex(4)  # 8 hex chars
        return f"{prefix}_{part1}_{part2}"
    
    @classmethod
    def register_device(cls, device_token: str, device_name: str = "", 
                       ip_address: str = None) -> DeviceAuthorization:
        """
        Register a new device token.
        
        Args:
            device_token: The unique token generated by desktop
            device_name: Optional name for the device
            ip_address: IP address of the request
            
        Returns:
            The created DeviceAuthorization record
        """
        expires_at = timezone.now() + timedelta(minutes=cls.TOKEN_EXPIRY_MINUTES)
        
        device_auth = DeviceAuthorization.objects.create(
            device_token=device_token,
            device_name=device_name,
            ip_address=ip_address,
            status='PENDING',
            expires_at=expires_at
        )
        
        AuditLog.log(
            action='DEVICE_REGISTERED',
            details=f"Device token registered: {device_token[:12]}..."
        )
        
        logger.info(f"Device registered with token {device_token[:12]}...")
        return device_auth
    
    @classmethod
    def get_device_status(cls, device_token: str) -> Tuple[Optional[DeviceAuthorization], str]:
        """
        Get the status of a device token.
        
        Args:
            device_token: The token to check
            
        Returns:
            Tuple of (DeviceAuthorization or None, status message)
        """
        try:
            device_auth = DeviceAuthorization.objects.get(device_token=device_token)
        except DeviceAuthorization.DoesNotExist:
            return None, "Token not found"
        
        # Check if expired
        if device_auth.is_expired and device_auth.status == 'PENDING':
            device_auth.status = 'EXPIRED'
            device_auth.save()
            return device_auth, "Token expired"
        
        return device_auth, device_auth.status
    
    @classmethod
    def approve_device(cls, device_token: str, user: User) -> Tuple[bool, str, Optional[DeviceAuthorization]]:
        """
        Approve a device authorization request.
        
        Args:
            device_token: The token to approve
            user: The user approving the device
            
        Returns:
            Tuple of (success, message, DeviceAuthorization)
        """
        device_auth, status = cls.get_device_status(device_token)
        
        if device_auth is None:
            return False, "Invalid token", None
        
        if status == 'EXPIRED':
            return False, "Token has expired. Please try again from the desktop app.", None
        
        if status == 'APPROVED':
            return False, "This device has already been authorized.", None
        
        if status == 'REVOKED':
            # A previously-revoked device token is being re-presented.
            # This happens when the desktop re-uses a device_token after session revocation
            # (e.g. the login dialog polled and got approved before revocation was processed).
            # Re-approve it so the fresh login establishes a clean session.
            logger.info(f"Re-approving previously-revoked device {device_token[:12]}... for {user.email}")
        
        # Approve (or re-approve) the device
        device_auth.user = user
        device_auth.status = 'APPROVED'
        device_auth.approved_at = timezone.now()
        device_auth.save()
        
        # Close any stale sessions for this device before creating a new one
        from core.models import ActiveSession
        ActiveSession.objects.filter(
            device_auth=device_auth,
            is_active=True
        ).update(is_active=False)
        
        AuditLog.log(
            action='DEVICE_AUTHORIZED',
            user=user,
            details=f"Device authorized: {device_token[:12]}..."
        )
        
        logger.info(f"Device {device_token[:12]}... approved for user {user.email}")
        return True, "Device authorized successfully", device_auth
    
    @classmethod
    def create_active_session(cls, user: User, device_auth: DeviceAuthorization,
                             jwt_jti: str, ip_address: str = None,
                             user_agent: str = "") -> ActiveSession:
        """
        Create an active session record for tracking.
        
        Args:
            user: The authenticated user
            device_auth: The approved device
            jwt_jti: The JWT token ID for revocation
            ip_address: Client IP address
            user_agent: Client user agent string
            
        Returns:
            The created ActiveSession
        """
        session = ActiveSession.objects.create(
            user=user,
            device_auth=device_auth,
            jwt_jti=jwt_jti,
            ip_address=ip_address,
            user_agent=user_agent[:500] if user_agent else ""
        )
        
        logger.info(f"Active session created for {user.email}")
        return session
    
    @classmethod
    def update_heartbeat(cls, device_token: str) -> Tuple[bool, str]:
        """
        Update the heartbeat timestamp for a device.
        
        Args:
            device_token: The device token
            
        Returns:
            Tuple of (is_valid, message)
        """
        try:
            device_auth = DeviceAuthorization.objects.get(device_token=device_token)
        except DeviceAuthorization.DoesNotExist:
            return False, "Device not found"
        
        if device_auth.status != 'APPROVED':
            return False, f"Device status is {device_auth.status}"
        
        device_auth.last_heartbeat = timezone.now()
        device_auth.save()
        
        return True, "Heartbeat recorded"
    
    @classmethod
    def revoke_session(cls, session_id: str, revoked_by: User) -> Tuple[bool, str]:
        """
        Revoke an active session.
        
        Args:
            session_id: The session UUID to revoke
            revoked_by: The admin user revoking the session
            
        Returns:
            Tuple of (success, message)
        """
        try:
            session = ActiveSession.objects.get(id=session_id)
        except ActiveSession.DoesNotExist:
            return False, "Session not found"
        
        if not session.is_active:
            return False, "Session already revoked"
        
        # Revoke the session
        session.revoke()
        
        AuditLog.log(
            action='SESSION_REVOKED',
            user=revoked_by,
            details=f"Revoked session for {session.user.email}",
            related_object=session
        )
        
        logger.info(f"Session {session_id} revoked by {revoked_by.email}")
        return True, "Session revoked successfully"
    
    @classmethod
    def get_active_sessions(cls, organization=None) -> list:
        """
        Get all active sessions, optionally filtered by organization.
        
        Args:
            organization: Optional organization to filter by
            
        Returns:
            List of ActiveSession objects
        """
        queryset = ActiveSession.objects.filter(is_active=True)
        if organization:
            queryset = queryset.filter(user__organization=organization)
        return queryset.select_related('user', 'device_auth')
    
    @classmethod
    def check_session_validity(cls, jwt_jti: str) -> Tuple[bool, str]:
        """
        Check if a session is still valid by JWT ID.
        
        Args:
            jwt_jti: The JWT token ID
            
        Returns:
            Tuple of (is_valid, message)
        """
        try:
            session = ActiveSession.objects.get(jwt_jti=jwt_jti)
        except ActiveSession.DoesNotExist:
            return False, "Session not found"
        
        if not session.is_active:
            return False, "Session has been revoked"
        
        if not session.device_auth.is_valid:
            return False, "Device authorization is no longer valid"
        
        return True, "Session is valid"
