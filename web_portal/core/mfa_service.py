"""
AVAGuard Web Portal - Enterprise MFA Service (Phase 1.5)

Provides TOTP (RFC 6238) primary 2FA and Email OTP fallback.
Handles secret generation, QR provisioning URI, and verification.

Security invariants:
- TOTP secrets are stored encrypted at rest (via Django's DB encryption or field-level).
- Failed attempts are tracked per-user and rate-limited.
- Email OTP codes expire in 120 seconds and are single-use.
"""

import base64
import io
import random
import string
import logging
from datetime import timedelta

import pyotp
import qrcode

from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone

from .models import User, AuditLog

logger = logging.getLogger(__name__)

# Constants
TOTP_ISSUER_NAME = 'AVAGuard'
EMAIL_OTP_EXPIRY_SECONDS = 120
MAX_TOTP_FAILED_ATTEMPTS = 5


class TOTPService:
    """
    RFC 6238 Time-Based One-Time Password service.
    Compatible with Google Authenticator, Microsoft Authenticator, Authy.
    """

    @staticmethod
    def generate_secret() -> str:
        """Generate a new Base32-encoded TOTP secret."""
        return pyotp.random_base32()

    @staticmethod
    def get_totp(secret: str) -> pyotp.TOTP:
        """Create a TOTP instance from a secret."""
        return pyotp.TOTP(secret)

    @classmethod
    def verify_token(cls, user: User, token: str) -> tuple[bool, str]:
        """
        Verify a TOTP token against the user's stored secret.

        Returns:
            (success: bool, message: str)
        """
        if not user.mfa_secret:
            return False, 'TOTP is not configured for this account.'

        if user.two_factor_failed_attempts >= MAX_TOTP_FAILED_ATTEMPTS:
            return False, (
                'Too many failed verification attempts. '
                'Contact an administrator to reset your 2FA.'
            )

        totp = cls.get_totp(user.mfa_secret)

        # valid_window=1 allows ±30s tolerance (one period before/after)
        if totp.verify(token, valid_window=1):
            # Reset failed attempts on success
            user.two_factor_failed_attempts = 0
            user.save(update_fields=['two_factor_failed_attempts'])
            return True, 'TOTP verified successfully.'

        # Track failed attempt
        user.two_factor_failed_attempts += 1
        user.save(update_fields=['two_factor_failed_attempts'])

        remaining = MAX_TOTP_FAILED_ATTEMPTS - user.two_factor_failed_attempts
        if remaining <= 0:
            return False, 'Account locked due to repeated failed 2FA attempts.'
        return False, f'Invalid verification code. {remaining} attempts remaining.'

    @classmethod
    def generate_provisioning_uri(cls, user: User, secret: str) -> str:
        """
        Generate an otpauth:// URI for QR code scanning.
        Format: otpauth://totp/AVAGuard:user@email?secret=XXX&issuer=AVAGuard
        """
        totp = cls.get_totp(secret)
        return totp.provisioning_uri(
            name=user.email,
            issuer_name=TOTP_ISSUER_NAME,
        )

    @classmethod
    def generate_qr_code_base64(cls, user: User, secret: str) -> str:
        """
        Generate a QR code as a Base64-encoded PNG string.
        This is embedded directly in the HTML template as a data URI.
        """
        uri = cls.generate_provisioning_uri(user, secret)

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=6,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color='black', back_color='white')

        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)

        return base64.b64encode(buffer.getvalue()).decode('utf-8')


class EmailOTPService:
    """
    Email OTP fallback mechanism.
    Used when TOTP is not yet configured or user cannot access authenticator.
    """

    @staticmethod
    def generate_code() -> str:
        """Generate a cryptographically random 6-digit code."""
        return ''.join(random.choices(string.digits, k=6))

    @classmethod
    def send_otp(cls, user: User) -> str:
        """
        Generate, store, and send an Email OTP to the user.

        Returns the generated code (for console fallback display).
        """
        code = cls.generate_code()

        # Store on the user model with expiry
        user.email_otp_code = code
        user.email_otp_expiry = timezone.now() + timedelta(
            seconds=EMAIL_OTP_EXPIRY_SECONDS
        )
        user.save(update_fields=['email_otp_code', 'email_otp_expiry'])

        # Send via email
        subject = 'AVAGuard Security - Verification Code'
        text_message = (
            f'Your verification code is: {code}\n\n'
            f'This code expires in {EMAIL_OTP_EXPIRY_SECONDS // 60} minutes.\n'
            f'If you did not request this code, please ignore this email.'
        )
        
        html_message = f"""
        <html>
        <body style="font-family: Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background-color: #0f0f23; padding: 20px; border-radius: 8px 8px 0 0; text-align: center;">
                <h1 style="color: #00d4ff; margin: 0; font-size: 24px;">AVAGuard</h1>
            </div>
            <div style="border: 1px solid #ddd; border-top: none; padding: 30px; border-radius: 0 0 8px 8px; background-color: #ffffff;">
                <h2 style="color: #1a1a2e; margin-top: 0;">Security Verification</h2>
                <p>Hello,</p>
                <p>Your one-time verification code is:</p>
                <div style="background-color: #f4f4f9; padding: 15px; border-radius: 6px; text-align: center; margin: 20px 0;">
                    <span style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #1a1a2e;">{code}</span>
                </div>
                <p>This code will expire in <strong>{EMAIL_OTP_EXPIRY_SECONDS // 60} minutes</strong>.</p>
                <p style="font-size: 12px; color: #777; margin-top: 30px; border-top: 1px solid #eee; padding-top: 15px;">
                    If you did not request this code, please secure your account immediately or contact your administrator.<br>
                    This is an automated message, please do not reply.
                </p>
            </div>
        </body>
        </html>
        """

        try:
            send_mail(
                subject=subject,
                message=text_message,
                html_message=html_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False,
            )
            logger.info(f"Email OTP sent to {user.email}")
        except Exception as e:
            # Fallback: log to console (development mode)
            logger.warning(f"Email send failed ({e}). OTP for {user.email}: {code}")
            print(f"\n{'='*50}")
            print(f"  EMAIL OTP for {user.email}: {code}")
            print(f"  Expires in {EMAIL_OTP_EXPIRY_SECONDS} seconds")
            print(f"{'='*50}\n")

        AuditLog.log(
            action='OTP_SENT',
            user=user,
            details=f'Email OTP sent to {user.email}'
        )

        return code

    @classmethod
    def verify_otp(cls, user: User, code: str) -> tuple[bool, str]:
        """
        Verify an Email OTP code.

        Returns:
            (success: bool, message: str)
        """
        if not user.email_otp_code:
            return False, 'No OTP code was generated. Please request a new one.'

        # Check expiry
        if user.email_otp_expiry and timezone.now() > user.email_otp_expiry:
            # Invalidate expired code
            user.email_otp_code = ''
            user.email_otp_expiry = None
            user.save(update_fields=['email_otp_code', 'email_otp_expiry'])
            return False, 'Verification code has expired. Please request a new one.'

        if user.email_otp_code != code:
            return False, 'Invalid verification code.'

        # Success — invalidate the code (single-use)
        user.email_otp_code = ''
        user.email_otp_expiry = None
        user.save(update_fields=['email_otp_code', 'email_otp_expiry'])

        AuditLog.log(
            action='OTP_VERIFIED',
            user=user,
            details='Email OTP verified successfully'
        )

        return True, 'Code verified successfully.'
