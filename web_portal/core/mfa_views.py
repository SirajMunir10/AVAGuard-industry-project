"""
AVAGuard Web Portal - MFA Views (Phase 1.5)

Handles the Enterprise Authentication flow:
- MFA Gateway: Intercepts login to route to TOTP or Email OTP verification
- TOTP Setup: Mandatory onboarding page for users without authenticator app
- Sudo Confirmation: Re-authentication endpoint for destructive actions
"""

import logging
from django.shortcuts import render, redirect
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.utils import timezone

from .models import User, AuditLog
from .mfa_service import TOTPService, EmailOTPService
from .security import set_sudo_timestamp

from django.views.decorators.cache import never_cache

logger = logging.getLogger(__name__)


@never_cache
def mfa_verify_view(request):
    """
    MFA Verification Gateway (Layer 2).

    After password verification succeeds, the user is redirected here.
    Routes to TOTP or Email OTP input based on user configuration.
    """
    # Get the pending user from session
    pending_user_id = request.session.get('mfa_pending_user_id')
    if not pending_user_id:
        messages.error(request, 'Session expired. Please log in again.')
        return redirect('login')

    try:
        user = User.objects.get(pk=pending_user_id, is_active=True)
    except User.DoesNotExist:
        messages.error(request, 'Account not found.')
        return redirect('login')

    # ── Account Expiry Enforcement (defence-in-depth) ──
    if user.is_expired:
        request.session.pop('mfa_pending_user_id', None)
        messages.error(request, 'This account has expired. Please contact your administrator.')
        return redirect('login')

    # ── 2FA Bypass Check ──
    # If admin has disabled MFA for this user, skip verification entirely
    if not user.mfa_enabled and not user.mfa_secret:
        login(request, user)
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])
        request.session.pop('mfa_pending_user_id', None)

        AuditLog.log(
            action='LOGIN',
            user=user,
            details='Web login successful (MFA: BYPASSED — disabled by admin)',
            ip_address=_get_client_ip(request),
        )
        messages.success(request, f'Welcome back, {user.full_name}!')

        # Check for device authorization token
        device_token = request.session.pop('pending_device_token', None)
        if device_token:
            return redirect(f'/auth/authorize-device/?token={device_token}')
        return redirect('dashboard')

    # Determine which MFA method to use
    default_mfa = 'totp' if (user.mfa_enabled and user.mfa_secret) else 'email'
    mfa_method = request.session.get('mfa_method_override', default_mfa)

    context = {
        'mfa_method': mfa_method,
        'email': user.email,
        'active_page': 'login',
    }

    if request.method == 'POST':
        action = request.POST.get('action', '')

        # Handle "Send Email OTP" button
        if action == 'send_email_otp':
            EmailOTPService.send_otp(user)
            messages.info(request, 'Verification code sent to your email.')
            request.session['mfa_method_override'] = 'email'
            context['mfa_method'] = 'email'
            context['email_sent'] = True
            return render(request, 'auth/mfa_verify.html', context)

        # Handle code submission
        code = request.POST.get('code', '').strip()
        if not code:
            messages.error(request, 'Please enter a verification code.')
            return render(request, 'auth/mfa_verify.html', context)

        # Verify based on method
        if mfa_method == 'totp':
            success, msg = TOTPService.verify_token(user, code)
        else:
            success, msg = EmailOTPService.verify_otp(user, code)

        if not success:
            messages.error(request, msg)
            return render(request, 'auth/mfa_verify.html', context)

        # MFA verified — complete login
        login(request, user)
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])

        # Clean up session
        request.session.pop('mfa_pending_user_id', None)
        request.session.pop('mfa_method_override', None)

        AuditLog.log(
            action='LOGIN',
            user=user,
            details=f'Web login successful (MFA: {mfa_method.upper()})',
            ip_address=_get_client_ip(request),
        )

        messages.success(request, f'Welcome back, {user.full_name}!')

        # Check if TOTP is not yet configured — force setup
        if not user.mfa_secret:
            request.session['force_totp_setup'] = True
            return redirect('totp_setup')

        # Check for device authorization token
        device_token = request.session.pop('login_device_token', None)
        if device_token:
            return redirect(f'/auth/authorize-device/?token={device_token}')

        return redirect('dashboard')

    # GET — if method is email, auto-send OTP
    if mfa_method == 'email':
        if not request.session.get('mfa_email_otp_sent'):
            EmailOTPService.send_otp(user)
            request.session['mfa_email_otp_sent'] = True
            messages.info(request, 'A verification code has been sent to your email.')
            context['email_sent'] = True

    return render(request, 'auth/mfa_verify.html', context)


@never_cache
@login_required
def totp_setup_view(request):
    """
    Mandatory TOTP Onboarding Page.

    Forces users to scan a QR code and provision their authenticator app
    before accessing the dashboard. This mirrors Azure AD / Google Workspace.
    """
    user = request.user

    # Generate a new secret for setup (don't overwrite existing)
    setup_secret = request.session.get('totp_setup_secret')
    if not setup_secret:
        setup_secret = TOTPService.generate_secret()
        request.session['totp_setup_secret'] = setup_secret

    qr_code_base64 = TOTPService.generate_qr_code_base64(user, setup_secret)

    context = {
        'qr_code_base64': qr_code_base64,
        'secret_key': setup_secret,
        'active_page': 'settings',
    }

    if request.method == 'POST':
        code = request.POST.get('code', '').strip()
        if not code:
            messages.error(request, 'Please enter the 6-digit code from your authenticator app.')
            return render(request, 'auth/totp_setup.html', context)

        # Verify the code against the setup secret
        totp = TOTPService.get_totp(setup_secret)
        if not totp.verify(code, valid_window=1):
            messages.error(request, 'Invalid code. Please try again with the code from your authenticator app.')
            return render(request, 'auth/totp_setup.html', context)

        # Success — save the secret and activate TOTP
        user.mfa_secret = setup_secret
        user.mfa_enabled = True
        user.two_factor_method = 'TOTP'
        user.two_factor_failed_attempts = 0
        user.save(update_fields=[
            'mfa_secret', 'mfa_enabled', 'two_factor_method',
            'two_factor_failed_attempts',
        ])

        # Clean up session
        request.session.pop('totp_setup_secret', None)
        request.session.pop('force_totp_setup', None)

        AuditLog.log(
            action='TOTP_PROVISIONED',
            user=user,
            details='TOTP authenticator app provisioned successfully',
            ip_address=_get_client_ip(request),
        )

        messages.success(
            request,
            'Two-factor authentication has been set up successfully! '
            'Your account is now secured with your authenticator app.'
        )
        
        # Check for pending device authorization token (Scenario C: set_password → totp_setup → authorize)
        device_token = request.session.get('pending_device_token') or request.session.pop('login_device_token', None)
        if device_token:
            return redirect(f'/auth/authorize-device/?token={device_token}')
        return redirect('dashboard')

    return render(request, 'auth/totp_setup.html', context)


@require_POST
def sudo_confirm_view(request):
    """
    Sudo-mode re-authentication endpoint.

    Accepts password confirmation and sets a 5-minute sudo timestamp
    in the session. Used before destructive admin operations.
    """
    if not request.user.is_authenticated:
        return JsonResponse({
            'success': False,
            'errors': {'__all__': ['Authentication required.']},
        }, status=401)

    password = request.POST.get('password', '')
    if not password:
        return JsonResponse({
            'success': False,
            'errors': {'password': ['Password is required.']},
        }, status=400)

    if not request.user.check_password(password):
        AuditLog.log(
            action='LOGIN_FAILED',
            user=request.user,
            details='Sudo-mode re-authentication failed',
            ip_address=_get_client_ip(request),
        )
        return JsonResponse({
            'success': False,
            'errors': {'password': ['Incorrect password.']},
        }, status=403)

    # Set sudo timestamp
    set_sudo_timestamp(request)

    AuditLog.log(
        action='SUDO_CONFIRMED',
        user=request.user,
        details='Sudo-mode confirmed for destructive operations',
        ip_address=_get_client_ip(request),
    )

    return JsonResponse({
        'success': True,
        'message': 'Identity confirmed. You may proceed.',
        'valid_for_seconds': 300,
    })


def _get_client_ip(request):
    """Extract client IP from request headers."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '')
