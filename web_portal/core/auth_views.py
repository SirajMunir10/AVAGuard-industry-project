"""
AVAGuard Web Portal - Authentication Views

Web-based views for login, OTP verification, and device authorization.
These are the browser-facing pages (not API endpoints).
"""

import logging
from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.utils import timezone

from .models import User, DeviceAuthorization, ActiveSession, AuditLog
from .services import OTPService, DeviceAuthService
from .constants import ROLE_HIERARCHY

logger = logging.getLogger(__name__)


from django.views.decorators.cache import never_cache

@never_cache
def login_view(request):
    """
    Web login page with 2FA support.
    
    Step 1: User enters email/password
    Step 2: OTP is sent, user enters code
    """
    # ── Critical Issue 2: Save pending device token and source immediately ──
    # This must happen regardless of authentication state or request method.
    pending_token = request.GET.get('token') or request.POST.get('token')
    pending_source = request.GET.get('source') or request.POST.get('source')
    
    if pending_token:
        request.session['pending_device_token'] = pending_token
        if pending_source:
            request.session['pending_source'] = pending_source
            
    if request.user.is_authenticated:
        # Check if coming from device authorization
        device_token = pending_token or request.session.get('pending_device_token')
        if device_token:
            return redirect(f'/auth/authorize-device/?token={device_token}')
        return redirect('dashboard')
    
    context = {
        'step': 'credentials',  # or 'otp'
        'active_page': 'login',
    }
    
    # Helper to extract token from next URL or direct token parameter
    def extract_device_token(req):
        token = req.GET.get('token') or req.POST.get('token')
        if not token:
            next_url = req.GET.get('next') or req.POST.get('next', '')
            if 'token=' in next_url:
                import urllib.parse
                parsed = urllib.parse.urlparse(next_url)
                qs = urllib.parse.parse_qs(parsed.query)
                if 'token' in qs:
                    token = qs['token'][0]
        return token
    
    if request.method == 'POST':
        step = request.POST.get('step', 'credentials')
        
        if step == 'credentials':
            # Step 1: Validate email/password
            email = request.POST.get('email', '').strip()
            password = request.POST.get('password', '')
            
            if not email or not password:
                messages.error(request, 'Please enter email and password.')
                return render(request, 'auth/login.html', context)
            
            try:
                user = User.objects.get(email=email, is_active=True)
            except User.DoesNotExist:
                messages.error(request, 'Invalid email or password.')
                AuditLog.log(
                    action='LOGIN_FAILED',
                    details=f"Invalid email: {email}"
                )
                return render(request, 'auth/login.html', context)
            
            # ── Account Expiry Enforcement ──
            if user.is_expired:
                context['expired_user_id'] = user.id
                context['extension_status'] = user.extension_request_status
                
                msg = 'This account has expired.'
                if user.extension_request_status == 'PENDING':
                    msg += ' Your extension request is pending admin review.'
                elif user.extension_request_status == 'DENIED':
                    msg += ' Your extension request was denied. Please contact IT.'
                else:
                    msg += ' You may request an extension below.'
                    
                messages.error(request, msg)
                
                AuditLog.log(
                    action='LOGIN_BLOCKED_EXPIRED',
                    user=user,
                    details=f"Expired account login attempt: {email}"
                )
                return render(request, 'auth/login.html', context)
            
            if not user.check_password(password):
                messages.error(request, 'Invalid email or password.')
                AuditLog.log(
                    action='LOGIN_FAILED',
                    user=user,
                    details="Invalid password"
                )
                return render(request, 'auth/login.html', context)
            
            # ── Forced Password Change (SECURITY — must come before MFA) ──
            # If user must change password, log them in directly so the
            # FirstLoginMiddleware will intercept and redirect to set_password.
            # They CANNOT access anything else — the middleware enforces this.
            # After password change, set_password_view routes to totp_setup
            # if MFA is not yet configured.
            if getattr(user, 'is_first_login', False) or getattr(user, 'password_change_required', False):
                login(request, user)
                user.last_login = timezone.now()
                user.save(update_fields=['last_login'])
                
                AuditLog.log(
                    action='LOGIN',
                    user=user,
                    details='Web login successful (Password change required — MFA bypassed)'
                )
                
                # Store device token in session so it survives password change + TOTP setup redirects
                # (Scenario B/D: first-login user hits set_password then totp_setup)
                device_token = extract_device_token(request)
                if device_token:
                    request.session['login_device_token'] = device_token
                
                # FirstLoginMiddleware will redirect to set_password
                return redirect('set_password')
            
            # ── Enterprise MFA Gateway (Phase 1.5) ──
            # Route through MFA only if user has MFA enabled.
            # If admin has disabled MFA for this user, bypass entirely.
            
            if user.mfa_enabled or user.mfa_secret:
                # User has MFA configured — route to verification
                request.session['mfa_pending_user_id'] = str(user.pk)
                request.session['mfa_email_otp_sent'] = False
                
                # Preserve device token if present
                device_token = extract_device_token(request)
                if device_token:
                    request.session['login_device_token'] = device_token
                
                return redirect('mfa_verify')
            else:
                # MFA disabled for this user — log in directly
                login(request, user)
                user.last_login = timezone.now()
                user.save(update_fields=['last_login'])
                
                AuditLog.log(
                    action='LOGIN',
                    user=user,
                    details='Web login successful (MFA: DISABLED)'
                )
                
                messages.success(request, f'Welcome back, {user.full_name}!')
                
                # Check for device authorization token
                device_token = extract_device_token(request)
                if device_token:
                    return redirect(f'/auth/authorize-device/?token={device_token}')
                
                return redirect('dashboard')
            
        elif step == 'otp':
            # Handle Resend
            if request.POST.get('resend'):
                email = request.session.get('login_email')
                if not email:
                    messages.error(request, 'Session expired. Please login again.')
                    return render(request, 'auth/login.html', context)
                    
                try:
                    user = User.objects.get(email=email, is_active=True)
                    # Resend logic
                    session_id = OTPService.generate_session_id()
                    code = OTPService.generate_otp(user, session_id)
                    OTPService.send_otp(user, code)
                    
                    request.session['login_session_id'] = session_id
                    messages.success(request, 'New verification code sent!')
                    
                    context['step'] = 'otp'
                    context['email'] = email
                    return render(request, 'auth/login.html', context)
                    
                except User.DoesNotExist:
                     messages.error(request, 'User not found.')
                     return render(request, 'auth/login.html', context)
            
            # Step 2: Verify OTP
            # Step 2: Verify OTP
            email = request.session.get('login_email')
            session_id = request.session.get('login_session_id')
            code = request.POST.get('code', '').strip()
            
            if not all([email, session_id, code]):
                messages.error(request, 'Session expired. Please login again.')
                return render(request, 'auth/login.html', context)
            
            try:
                user = User.objects.get(email=email, is_active=True)
            except User.DoesNotExist:
                messages.error(request, 'User not found.')
                return render(request, 'auth/login.html', context)
            
            success, message = OTPService.verify_otp(user, code, session_id)
            
            if not success:
                context['step'] = 'otp'
                context['email'] = email
                messages.error(request, message)
                return render(request, 'auth/login.html', context)
            
            # Check if this is first login (before login() updates last_login)
            if user.last_login is None:
                request.session['force_password_change'] = True
            
            # OTP verified - login the user
            login(request, user)
            
            # Update last login
            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])
            
            # Clear session data
            request.session.pop('login_email', None)
            request.session.pop('login_session_id', None)
            
            AuditLog.log(
                action='LOGIN',
                user=user,
                details="Web login successful"
            )
            
            messages.success(request, f'Welcome back, {user.full_name}!')
            
            # Check for device authorization token
            # Check GET first, then POST (persisted in hidden field)
            device_token = extract_device_token(request)
            
            if device_token:
                return redirect(f'/auth/authorize-device/?token={device_token}')
            
            return redirect('dashboard')
    
    return render(request, 'auth/login.html', context)


def logout_view(request):
    """Log out the current user."""
    if request.user.is_authenticated:
        AuditLog.log(
            action='LOGOUT',
            user=request.user,
            details="User logged out"
        )
    logout(request)
    messages.info(request, 'You have been logged out.')
    return redirect('login')


@login_required(login_url='/auth/login/')
def verify_otp_view(request):
    """Standalone OTP verification page."""
    # This is used when the user needs to re-verify
    return render(request, 'auth/verify_otp.html', {
        'active_page': 'verify_otp'
    })

def request_extension_view(request):
    """Handles submission of an account extension request from the login page."""
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        reason = request.POST.get('reason', '').strip()
        
        if not user_id or not reason:
            messages.error(request, 'Missing required information.')
            return redirect('login')
            
        try:
            user = User.objects.get(id=user_id)
            
            # Update user
            user.extension_requested = True
            user.extension_request_message = reason
            user.extension_request_status = 'PENDING'
            user.save(update_fields=['extension_requested', 'extension_request_message', 'extension_request_status'])
            
            # Create notification for super admins and IT admins
            from .models import Notification
            admin_users = User.objects.filter(role__in=['SUPER_ADMIN', 'IT_ADMIN'], is_active=True, organization=user.organization)
            
            notifications = []
            for admin in admin_users:
                notifications.append(Notification(
                    recipient=admin,
                    title="Account Extension Request",
                    message=f"{user.email} has requested an account extension. Reason: {reason}",
                    related_user=user,
                    action_url="/system/users/"
                ))
            
            if notifications:
                Notification.objects.bulk_create(notifications)
            
            messages.success(request, 'Your extension request has been submitted to the administrators.')
            
            AuditLog.log(
                action='EXTENSION_REQUESTED',
                user=user,
                details=f"Extension requested. Reason: {reason}"
            )
            
        except User.DoesNotExist:
            messages.error(request, 'User not found.')
            
    return redirect('login')

@never_cache
@login_required(login_url='/auth/login/')
def set_password_view(request):
    """
    First login or forced password reset view.
    Enforces strong password policy and prevents reuse.
    """
    if not getattr(request.user, 'is_first_login', False) and not getattr(request.user, 'password_change_required', False):
        return redirect('dashboard')
        
    context = {
        'active_page': 'set_password',
        'user': request.user
    }
    
    if request.method == 'POST':
        from .validators import NISTPasswordValidator
        
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')
        
        if not password or not confirm_password:
            messages.error(request, 'Both fields are required.')
            return render(request, 'auth/set_password.html', context)
            
        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'auth/set_password.html', context)
            
        # Prevent reuse of current password
        if request.user.check_password(password):
            messages.error(request, 'New password cannot be the same as your current/temporary password.')
            return render(request, 'auth/set_password.html', context)
            
        try:
            validator = NISTPasswordValidator()
            validator.validate(password)
        except Exception as e:
            messages.error(request, str(e))
            return render(request, 'auth/set_password.html', context)
            
        # Success - update password
        user = request.user
        user.set_password(password)
        user.is_first_login = False
        user.password_change_required = False
        user.password_last_changed = timezone.now()
        user.save()
        
        # We need to re-login the user because changing password clears their session
        from django.contrib.auth import update_session_auth_hash
        update_session_auth_hash(request, user)
        
        AuditLog.log(
            action='PASSWORD_CHANGED',
            user=user,
            details='Password updated during first login / forced reset flow'
        )
        
        messages.success(request, 'Password updated successfully.')
        
        # Continue to MFA setup if needed
        if not user.mfa_enabled:
            return redirect('totp_setup')
        
        # User already has MFA — check for pending device authorization (Scenario A)
        device_token = request.session.get('pending_device_token') or request.session.pop('login_device_token', None)
        if device_token:
            return redirect(f'/auth/authorize-device/?token={device_token}')
        return redirect('dashboard')
        
    return render(request, 'auth/set_password.html', context)

@never_cache
@login_required(login_url='/auth/login/')
def authorize_device_view(request):
    """
    Device authorization page.
    
    User approves a desktop app connection here.
    The token parameter comes from the URL that the desktop app opened.
    """
    device_token = request.GET.get('token', '') or request.POST.get('token', '') or request.session.get('pending_device_token', '')
    
    # If found in session, we can keep it until successful authorization or clear it now?
    # User said: "must read the token from session if not present in GET params as a fallback"
    
    if not device_token:
        # Show manual entry form
        return render(request, 'auth/authorize_device.html', {
            'active_page': 'authorize_device',
            'show_input_form': True
        })
    
    # Get device status
    device_auth, status_msg = DeviceAuthService.get_device_status(device_token)
    
    context = {
        'active_page': 'authorize_device',
        'device_token': device_token,
        'device_auth': device_auth,
        'status_msg': status_msg,
    }
    
    if device_auth is None:
        messages.error(request, 'Invalid device token.')
        context['show_input_form'] = True
        return render(request, 'auth/authorize_device.html', context)
    
    if device_auth.status == 'EXPIRED':
        messages.error(request, 'This device token has expired. Please restart the desktop app.')
        return render(request, 'auth/authorize_device.html', context)
    
    if device_auth.status == 'APPROVED':
        messages.info(request, 'This device has already been authorized.')
        return render(request, 'auth/authorize_device.html', context)
    
    if request.method == 'POST':
        # Approve the device
        success, message, device_auth = DeviceAuthService.approve_device(
            device_token, 
            request.user
        )
        
        if success:
            messages.success(request, 'Device authorized! You can now use the desktop app.')
            context['device_auth'] = device_auth
            context['approved'] = True
            
            # Clear pending session tokens
            request.session.pop('pending_device_token', None)
            request.session.pop('pending_source', None)
            request.session.pop('login_device_token', None) # Legacy key just in case
        else:
            messages.error(request, message)
    
    return render(request, 'auth/authorize_device.html', context)


# ==============================================================================
# Admin Views
# ==============================================================================

def admin_required(view_func):
    """Decorator to require admin role."""
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        if request.user.role not in ['SUPER_ADMIN', 'IT_ADMIN']:
            messages.error(request, 'Admin access required.')
            return redirect('dashboard')
        return view_func(request, *args, **kwargs)
    return wrapper


@login_required(login_url='/auth/login/')
def user_management_view(request):
    """
    User management page for Super Admins.
    CRUD operations on users and filtered views for security alerts.
    """
    if request.user.role != 'SUPER_ADMIN':
        messages.error(request, 'Access restricted to Super Administrators.')
        return redirect('dashboard')

    context = {
        'active_page': 'users',
    }
    
    # Get users for the organization
    users = User.objects.filter(
        organization=request.user.organization
    )

    # ── Filtering Logic (Dashboard Integration) ──
    filter_mfa = request.GET.get('mfa_disabled') == 'true'
    filter_expiry = request.GET.get('expiring_soon') == 'true'

    if filter_mfa:
        users = users.filter(mfa_enabled=False)
        context['active_filter_label'] = 'Users with 2FA Disabled'
    elif filter_expiry:
        seven_days = timezone.now() + timezone.timedelta(days=7)
        users = users.filter(expires_at__isnull=False, expires_at__lte=seven_days)
        context['active_filter_label'] = 'Accounts Expiring Soon'

    users = users.order_by('email')
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'create':
            # Create new user
            email = request.POST.get('email', '').strip()
            first_name = request.POST.get('first_name', '').strip()
            last_name = request.POST.get('last_name', '').strip()
            role = request.POST.get('role', 'VIEWER')
            department = request.POST.get('department', '').strip()
            
            password = request.POST.get('password', '').strip()
            confirm_password = request.POST.get('confirm_password', '').strip()
            
            if not email:
                messages.error(request, 'Email is required.')
            elif not password:
                messages.error(request, 'Password is required.')
            elif password != confirm_password:
                messages.error(request, 'Passwords do not match.')
            elif len(password) < 8:
                messages.error(request, 'Password must be at least 8 characters.')
            elif User.objects.filter(email=email).exists():
                messages.error(request, 'A user with this email already exists.')
            else:
                user = User.objects.create_user(
                    email=email,
                    password=password,
                    first_name=first_name,
                    last_name=last_name,
                    role=role,
                    department=department,
                    organization=request.user.organization,
                )
                
                AuditLog.log(
                    action='USER_CREATED',
                    user=request.user,
                    details=f"Created user: {email} with role {role}",
                    related_object=user
                )
                
                messages.success(request, f'User {email} created successfully.')
        
        elif action == 'delete':
            user_id = request.POST.get('user_id')
            try:
                user = User.objects.get(id=user_id)
                email = user.email
                
                # Prevent self-deletion
                if user.id == request.user.id:
                    messages.error(request, 'You cannot delete yourself.')
                else:
                    user.delete()
                    AuditLog.log(
                        action='USER_DELETED',
                        user=request.user,
                        details=f"Deleted user: {email}"
                    )
                    messages.success(request, f'User {email} deleted.')
            except User.DoesNotExist:
                messages.error(request, 'User not found.')
        
        elif action == 'update_role':
            user_id = request.POST.get('user_id')
            new_role = request.POST.get('role')
            try:
                user = User.objects.get(id=user_id)
                old_role = user.role
                user.role = new_role
                user.save()
                
                AuditLog.log(
                    action='USER_UPDATED',
                    user=request.user,
                    details=f"Changed role for {user.email}: {old_role} -> {new_role}"
                )
                messages.success(request, f'Updated role for {user.email}.')
            except User.DoesNotExist:
                messages.error(request, 'User not found.')
    
    # Get users for the organization
    users = User.objects.filter(
        organization=request.user.organization
    ).order_by('email')
    
    context['users'] = users
    context['role_choices'] = User.ROLE_CHOICES
    
    return render(request, 'admin/users.html', context)


def active_sessions_view(request):
    """
    Active sessions page for admins (Phase 3 — Hardened).

    Supports:
    - Self-revocation protection (never revoke own session)
    - Bulk revocation with 500-cap and impact summary
    - AJAX JSON responses for revocation actions
    """
    context = {
        'active_page': 'sessions',
    }

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'revoke_user_sessions' or action == 'revoke':
            # Revoke all active sessions for the selected users
            revoke_all = request.POST.get('revoke_all') == 'true'
            # Fallback to session_ids if coming from old UI or the details page
            session_ids = request.POST.getlist('session_ids') or [request.POST.get('session_id')]
            session_ids = [s for s in session_ids if s]
            
            user_ids = request.POST.getlist('user_ids') or [request.POST.get('user_id')]
            user_ids = [u for u in user_ids if u]

            REVOKE_LIMIT = 500
            revoked = 0
            skipped_self = 0
            skipped_hierarchy = 0

            if revoke_all:
                sessions = ActiveSession.objects.filter(
                    user__organization=request.user.organization,
                    is_active=True,
                ).exclude(user=request.user)[:REVOKE_LIMIT]
            elif user_ids:
                sessions = ActiveSession.objects.filter(
                    user_id__in=user_ids,
                    user__organization=request.user.organization,
                    is_active=True,
                )[:REVOKE_LIMIT]
            elif session_ids:
                sessions = ActiveSession.objects.filter(
                    id__in=session_ids,
                    user__organization=request.user.organization,
                    is_active=True,
                )
            else:
                messages.error(request, 'No users or sessions specified.')
                return redirect('active_sessions')

            for session in sessions:
                if session.user_id == request.user.id:
                    skipped_self += 1
                    continue

                request_user_rank = ROLE_HIERARCHY.get(request.user.role, 0)
                target_user_rank = ROLE_HIERARCHY.get(session.user.role, 0)

                if request_user_rank < target_user_rank:
                    skipped_hierarchy += 1
                    continue

                session.revoke()
                revoked += 1

            details = f"Revoked {revoked} session(s)"
            if skipped_self > 0:
                details += f", {skipped_self} skipped (self-protection)"
            if skipped_hierarchy > 0:
                details += f", {skipped_hierarchy} skipped (hierarchy-protection)"

            AuditLog.log(
                action='SESSION_REVOKED',
                user=request.user,
                details=details,
                ip_address=request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
                    or request.META.get('REMOTE_ADDR', ''),
            )

            msg = f"Successfully revoked {revoked} session(s)."
            if skipped_self > 0:
                msg += f" {skipped_self} session(s) skipped (cannot revoke your own)."
            if skipped_hierarchy > 0:
                msg += f" {skipped_hierarchy} session(s) skipped (hierarchy restricted)."

            messages.add_message(request, messages.SUCCESS, msg)
            
            # If a return_url was provided (e.g. from detail page), go there
            return_url = request.POST.get('return_url')
            if return_url:
                return redirect(return_url)
            return redirect('active_sessions')

    # GET — render users list with active sessions
    from django.db.models import Q, Count, Max, Prefetch
    from django.core.paginator import Paginator

    active_sessions_prefetch = Prefetch(
        'active_sessions',
        queryset=ActiveSession.objects.filter(is_active=True).select_related('device_auth').order_by('-last_activity'),
        to_attr='current_active_sessions'
    )

    queryset = User.objects.filter(
        organization=request.user.organization,
    ).annotate(
        active_session_count=Count('active_sessions', filter=Q(active_sessions__is_active=True)),
        max_last_activity=Max('active_sessions__last_activity', filter=Q(active_sessions__is_active=True))
    ).filter(
        active_session_count__gt=0
    ).prefetch_related(active_sessions_prefetch)

    # Search filtering
    search_query = request.GET.get('q', '')
    if search_query:
        queryset = queryset.filter(
            Q(email__icontains=search_query) |
            Q(first_name__icontains=search_query) |
            Q(last_name__icontains=search_query)
        )

    # Role filtering
    role_filter = request.GET.get('role', '')
    if role_filter:
        queryset = queryset.filter(role=role_filter)

    # Sorting
    sort_param = request.GET.get('sort', '-latest_activity')
    if sort_param == 'user':
        queryset = queryset.order_by('email')
    elif sort_param == '-user':
        queryset = queryset.order_by('-email')
    elif sort_param == 'role':
        queryset = queryset.order_by('role')
    elif sort_param == '-role':
        queryset = queryset.order_by('-role')
    elif sort_param == 'sessions':
        queryset = queryset.order_by('active_session_count')
    elif sort_param == '-sessions':
        queryset = queryset.order_by('-active_session_count')
    elif sort_param == 'latest_activity':
        queryset = queryset.order_by('max_last_activity')
    else:
        queryset = queryset.order_by('-max_last_activity')

    # Unique user count for stats
    unique_users = queryset.count()

    # Pagination
    paginator = Paginator(queryset, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Annotate properties for the template
    request_user_rank = ROLE_HIERARCHY.get(request.user.role, 0)
    for u in page_obj:
        target_rank = ROLE_HIERARCHY.get(u.role, 0)
        u.can_revoke = (request_user_rank >= target_rank) and (u.id != request.user.id)
        
        # Determine primary session and stale status
        u.is_stale = True
        u.primary_device_name = "Unknown Device"
        u.primary_ip = "Unknown IP"
        u.latest_activity = None
        u.stale_count = 0
        u.active_count = 0
        
        if u.current_active_sessions:
            primary = u.current_active_sessions[0]
            u.primary_device_name = primary.device_auth.device_name if (primary.device_auth and primary.device_auth.device_name) else "Unknown Device"
            u.primary_ip = primary.ip_address or "Unknown IP"
            u.latest_activity = primary.last_activity
            u.is_stale = all(s.is_stale for s in u.current_active_sessions)
            u.stale_count = sum(1 for s in u.current_active_sessions if s.is_stale)
            u.active_count = u.active_session_count - u.stale_count

    context['users_page'] = page_obj
    context['search_query'] = search_query
    context['role_filter'] = role_filter
    context['unique_users'] = unique_users

    return render(request, 'admin/sessions.html', context)


