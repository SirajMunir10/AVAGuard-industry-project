"""
AVAGuard Web Portal - User Management Views (Phase 2 — Hardened)

AJAX endpoints for advanced user management with Phase 0.5 security enforcement:
- RBAC hierarchy checks (prevent privilege escalation)
- Sudo-mode for destructive operations
- Optimistic locking via updated_at timestamps
- Standardized error JSON format
"""

import json
import logging
from datetime import datetime
from django.http import JsonResponse
from django.views.decorators.http import require_POST, require_GET
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from django.db.models import Q

from .models import User, ActiveSession, AuditLog
from .security import (
    enforce_role_hierarchy,
    can_modify_user,
    validate_role_assignment,
    is_sudo_valid,
    get_role_weight,
    check_optimistic_lock,
)

logger = logging.getLogger(__name__)


# ======================================================================
# Decorators — Standardized Access Control
# ======================================================================

def admin_required(view_func):
    """Decorator: requires SUPER_ADMIN or IT_ADMIN role."""
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({
                'success': False,
                'errors': {'__all__': ['Authentication required.']},
            }, status=401)
        if request.user.role not in ['SUPER_ADMIN', 'IT_ADMIN']:
            return JsonResponse({
                'success': False,
                'errors': {'__all__': ['Admin access required.']},
            }, status=403)
        return view_func(request, *args, **kwargs)
    return wrapper


def super_admin_required(view_func):
    """Decorator: requires SUPER_ADMIN role only."""
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({
                'success': False,
                'errors': {'__all__': ['Authentication required.']},
            }, status=401)
        if request.user.role != 'SUPER_ADMIN':
            return JsonResponse({
                'success': False,
                'errors': {'__all__': ['Super Admin access required.']},
            }, status=403)
        return view_func(request, *args, **kwargs)
    return wrapper


def _get_client_ip(request):
    """Extract client IP from request."""
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    if xff:
        return xff.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '')


# ======================================================================
# Phase 1.5: Admin 2FA Reset (Admin Override)
# ======================================================================

@require_POST
@csrf_protect
@super_admin_required
def reset_user_2fa(request, user_id):
    """
    Reset a user's TOTP 2FA configuration (Admin Override).

    Requires sudo-mode. Deletes the TOTP secret, invalidates active
    sessions, and forces re-provisioning on next login.

    POST /api/users/<uuid>/reset-2fa/
    """
    try:
        target_user = User.objects.get(id=user_id)

        # 0.5A: RBAC hierarchy check
        rbac_error = enforce_role_hierarchy(request.user, target_user)
        if rbac_error:
            return rbac_error

        # 0.5B: Require sudo-mode for this destructive action
        if not is_sudo_valid(request):
            return JsonResponse({
                'success': False,
                'sudo_required': True,
                'errors': {'__all__': [
                    'This action requires re-authentication. '
                    'Please confirm your password to continue.'
                ]},
            }, status=403)

        # Perform the 2FA reset
        target_user.mfa_secret = ''
        target_user.mfa_enabled = False
        target_user.two_factor_method = 'EMAIL'
        target_user.two_factor_failed_attempts = 0
        target_user.modified_by = request.user
        target_user.save(update_fields=[
            'mfa_secret', 'mfa_enabled', 'two_factor_method',
            'two_factor_failed_attempts', 'modified_by', 'updated_at',
        ])

        # Invalidate all active sessions
        sessions = ActiveSession.objects.filter(user=target_user, is_active=True)
        sessions_revoked = sessions.count()
        for session in sessions:
            session.revoke()

        # Audit log
        AuditLog.log(
            action='MFA_RESET_BY_ADMIN',
            user=request.user,
            details=(
                f"Admin {request.user.email} reset 2FA for {target_user.email}. "
                f"{sessions_revoked} sessions revoked."
            ),
            ip_address=_get_client_ip(request),
            related_object=target_user,
        )

        logger.info(
            f"Admin {request.user.email} reset 2FA for {target_user.email}"
        )

        return JsonResponse({
            'success': True,
            'sessions_revoked': sessions_revoked,
            'message': (
                f"2FA reset for {target_user.email}. "
                f"They will be required to re-configure TOTP on next login."
            ),
        })

    except User.DoesNotExist:
        return JsonResponse({
            'success': False,
            'errors': {'__all__': ['User not found.']},
        }, status=404)
    except Exception as e:
        logger.error(f"Error resetting 2FA: {e}")
        return JsonResponse({
            'success': False,
            'errors': {'__all__': ['An unexpected error occurred.']},
        }, status=500)


# ======================================================================
# User Status Management (Hardened)
# ======================================================================

@require_POST
@csrf_protect
@admin_required
def toggle_user_status(request, user_id):
    """
    Activate or soft-deactivate a user account. Kill Switch on deactivation.

    Enforces: RBAC hierarchy, sudo-mode for deactivation.
    POST /api/users/<uuid>/toggle-status/
    """
    try:
        target_user = User.objects.get(id=user_id)

        # 0.5A: RBAC hierarchy
        rbac_error = enforce_role_hierarchy(request.user, target_user)
        if rbac_error:
            return rbac_error

        # Deactivation is a destructive action — require sudo
        if target_user.is_active and not is_sudo_valid(request):
            return JsonResponse({
                'success': False,
                'sudo_required': True,
                'errors': {'__all__': [
                    'Deactivating a user requires re-authentication.'
                ]},
            }, status=403)

        # Toggle
        old_status = target_user.is_active
        target_user.is_active = not old_status
        target_user.modified_by = request.user
        
        # 4. Auto-disable MFA when account is disabled
        mfa_disabled_msg = ""
        if not target_user.is_active:
            if target_user.mfa_enabled or target_user.mfa_secret:
                target_user.mfa_enabled = False
                target_user.mfa_secret = ''  # Clear TOTP secret
                mfa_disabled_msg = " and MFA auto-disabled"
                
        target_user.save(update_fields=['is_active', 'mfa_enabled', 'mfa_secret', 'modified_by', 'updated_at'])

        sessions_revoked = 0
        devices_revoked = 0
        if not target_user.is_active:
            active_sessions = ActiveSession.objects.filter(
                user=target_user, is_active=True
            )
            sessions_revoked = active_sessions.count()
            for session in active_sessions:
                session.revoke()
                
            devices = DeviceAuthorization.objects.filter(user=target_user, status='APPROVED')
            devices_revoked = devices.count()
            devices.update(status='REVOKED')

        action = 'ACCOUNT_ENABLED' if target_user.is_active else 'ACCOUNT_DISABLED'
        details = f"{action.replace('_', ' ')} for {target_user.email}{mfa_disabled_msg}"
        if sessions_revoked > 0 or devices_revoked > 0:
            details += f" ({sessions_revoked} web sessions, {devices_revoked} API tokens revoked)"

        AuditLog.log(
            action=action,
            user=request.user,
            details=details,
            ip_address=_get_client_ip(request),
            related_object=target_user,
        )

        return JsonResponse({
            'success': True,
            'is_active': target_user.is_active,
            'sessions_revoked': sessions_revoked + devices_revoked,
            'security_score': target_user.security_score,
            'message': f"Account {'enabled' if target_user.is_active else 'disabled'} for {target_user.email}",
        })

    except User.DoesNotExist:
        return JsonResponse({
            'success': False,
            'errors': {'__all__': ['User not found.']},
        }, status=404)
    except Exception as e:
        logger.error(f"Error toggling user status: {e}")
        return JsonResponse({
            'success': False,
            'errors': {'__all__': ['An unexpected error occurred.']},
        }, status=500)


# ======================================================================
# 2FA Toggle (Legacy — replaced by reset_user_2fa for admin override)
# ======================================================================

@require_POST
@csrf_protect
@super_admin_required
def toggle_user_2fa(request, user_id):
    """Toggle 2FA for a user. Requires RBAC hierarchy validation."""
    try:
        target_user = User.objects.get(id=user_id)

        # 0.5A: RBAC hierarchy
        rbac_error = enforce_role_hierarchy(request.user, target_user)
        if rbac_error:
            return rbac_error

        old_status = target_user.mfa_enabled
        target_user.mfa_enabled = not old_status
        target_user.modified_by = request.user
        target_user.save(update_fields=['mfa_enabled', 'modified_by', 'updated_at'])

        action = '2FA_ENABLED' if target_user.mfa_enabled else '2FA_DISABLED'
        AuditLog.log(
            action=action,
            user=request.user,
            details=f"{action.replace('_', ' ')} for {target_user.email}",
            ip_address=_get_client_ip(request),
            related_object=target_user,
        )

        return JsonResponse({
            'success': True,
            'mfa_enabled': target_user.mfa_enabled,
            'message': f"2FA {'enabled' if target_user.mfa_enabled else 'disabled'} for {target_user.email}",
        })

    except User.DoesNotExist:
        return JsonResponse({
            'success': False,
            'errors': {'__all__': ['User not found.']},
        }, status=404)
    except Exception as e:
        logger.error(f"Error toggling 2FA: {e}")
        return JsonResponse({
            'success': False,
            'errors': {'__all__': ['An unexpected error occurred.']},
        }, status=500)


# ======================================================================
# Force Password Reset & Invalidate Sessions (Hardened)
# ======================================================================

@require_POST
@csrf_protect
@admin_required
def invalidate_user_sessions(request, user_id):
    """
    Invalidate all active sessions for a user.
    Requires RBAC hierarchy validation.
    """
    try:
        target_user = User.objects.get(id=user_id)
        
        rbac_error = enforce_role_hierarchy(request.user, target_user)
        if rbac_error:
            return rbac_error

        # Require Sudo for session invalidation
        if not is_sudo_valid(request):
            return JsonResponse({
                'success': False,
                'sudo_required': True,
                'errors': {'__all__': ['Invalidating sessions requires re-authentication.']},
            }, status=403)

        active_sessions = ActiveSession.objects.filter(user=target_user, is_active=True)
        sessions_revoked = active_sessions.count()
        for session in active_sessions:
            session.revoke()
            
        devices = DeviceAuthorization.objects.filter(user=target_user, status='APPROVED')
        devices_revoked = devices.count()
        devices.update(status='REVOKED')
        
        total_revoked = sessions_revoked + devices_revoked
            
        AuditLog.log(
            action='SESSIONS_INVALIDATED',
            user=request.user,
            details=f"Invalidated {sessions_revoked} web sessions and {devices_revoked} API tokens for {target_user.email}",
            ip_address=_get_client_ip(request),
            related_object=target_user,
        )
        
        return JsonResponse({
            'success': True,
            'sessions_revoked': total_revoked,
            'message': f"Successfully revoked {sessions_revoked} web sessions and {devices_revoked} API tokens for {target_user.email}.",
        })
        
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'errors': {'__all__': ['User not found.']}}, status=404)
    except Exception as e:
        logger.error(f"Error invalidating sessions: {e}")
        return JsonResponse({'success': False, 'errors': {'__all__': ['An unexpected error occurred.']}}, status=500)
    

@require_POST
@csrf_protect
@admin_required
def force_password_reset(request, user_id):
    """
    Force a user to change their password (Azure AD-style workflow).

    Generates a secure 12-character temporary password, sets it on the
    user account, and flags password_change_required = True.

    The temporary password is returned ONCE in the JSON response so the
    admin can relay it to the user.  The user must change it on next login.
    """
    import secrets
    import string

    try:
        target_user = User.objects.get(id=user_id)

        rbac_error = enforce_role_hierarchy(request.user, target_user)
        if rbac_error:
            return rbac_error

        # Require sudo for this destructive action
        if not is_sudo_valid(request):
            return JsonResponse({
                'success': False,
                'sudo_required': True,
                'errors': {'__all__': [
                    'This action requires re-authentication.'
                ]},
            }, status=403)

        # Generate a secure 12-character temporary password
        alphabet = string.ascii_letters + string.digits + '!@#$%&*'
        temp_password = ''.join(secrets.choice(alphabet) for _ in range(12))

        # Set the temporary password on the user account
        target_user.set_password(temp_password)
        target_user.password_change_required = True
        target_user.password_last_changed = timezone.now()
        target_user.modified_by = request.user
        target_user.save(update_fields=[
            'password', 'password_change_required',
            'password_last_changed', 'modified_by', 'updated_at',
        ])

        # Invalidate all active sessions so old password can't be reused
        sessions = ActiveSession.objects.filter(user=target_user, is_active=True)
        sessions_revoked = sessions.count()
        for session in sessions:
            session.revoke()

        AuditLog.log(
            action='PASSWORD_RESET_FORCED',
            user=request.user,
            details=(
                f"Admin {request.user.email} reset password for "
                f"{target_user.email}. Temp password issued. "
                f"{sessions_revoked} sessions revoked."
            ),
            ip_address=_get_client_ip(request),
            related_object=target_user,
        )

        return JsonResponse({
            'success': True,
            'temp_password': temp_password,
            'sessions_revoked': sessions_revoked,
            'message': (
                f"Temporary password generated for {target_user.email}. "
                f"User must change it on next login."
            ),
        })

    except User.DoesNotExist:
        return JsonResponse({
            'success': False,
            'errors': {'__all__': ['User not found.']},
        }, status=404)
    except Exception as e:
        logger.error(f"Error forcing password reset: {e}")
        return JsonResponse({
            'success': False,
            'errors': {'__all__': ['An unexpected error occurred.']},
        }, status=500)


# ======================================================================
# Account Expiry (Hardened)
# ======================================================================

@require_POST
@csrf_protect
@admin_required
def set_user_expiry(request, user_id):
    """
    Set or clear an expiry date. Requires RBAC hierarchy.
    POST /api/users/<uuid>/set-expiry/
    Body: { "expires_at": "2024-12-31T23:59:59" } or { "expires_at": null }
    """
    try:
        target_user = User.objects.get(id=user_id)

        rbac_error = enforce_role_hierarchy(request.user, target_user)
        if rbac_error:
            return rbac_error

        data = json.loads(request.body)
        expires_at_str = data.get('expires_at')

        if expires_at_str:
            expires_at = datetime.fromisoformat(
                expires_at_str.replace('Z', '+00:00')
            )
            if timezone.is_naive(expires_at):
                expires_at = timezone.make_aware(expires_at)
            target_user.expires_at = expires_at
            
            # If there's a pending extension request and the date is moved forward, auto-approve it
            if target_user.extension_requested and target_user.extension_request_status == 'PENDING':
                if target_user.expires_at > timezone.now():
                    target_user.extension_request_status = 'APPROVED'
        else:
            target_user.expires_at = None
            # If removing expiry date entirely, also auto-approve any pending request
            if target_user.extension_requested and target_user.extension_request_status == 'PENDING':
                target_user.extension_request_status = 'APPROVED'

        target_user.modified_by = request.user
        target_user.save(update_fields=[
            'expires_at', 'modified_by', 'updated_at', 'extension_request_status'
        ])

        if target_user.expires_at:
            details = (
                f"Account expiry set to "
                f"{target_user.expires_at.strftime('%Y-%m-%d %H:%M')} "
                f"for {target_user.email}"
            )
        else:
            details = f"Account expiry removed for {target_user.email}"

        AuditLog.log(
            action='ACCOUNT_EXPIRY_SET',
            user=request.user,
            details=details,
            ip_address=_get_client_ip(request),
            related_object=target_user,
        )

        return JsonResponse({
            'success': True,
            'expires_at': (
                target_user.expires_at.isoformat()
                if target_user.expires_at else None
            ),
            'message': details,
        })

    except User.DoesNotExist:
        return JsonResponse({
            'success': False,
            'errors': {'__all__': ['User not found.']},
        }, status=404)
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'errors': {'__all__': ['Invalid JSON body.']},
        }, status=400)
    except Exception as e:
        logger.error(f"Error setting user expiry: {e}")
        return JsonResponse({
            'success': False,
            'errors': {'__all__': ['An unexpected error occurred.']},
        }, status=500)


# ======================================================================
# Bulk Actions (Hardened with cap limit)
# ======================================================================

@require_POST
@csrf_protect
@super_admin_required
def bulk_user_action(request):
    """
    Perform bulk action on users. Hard-capped at 500.
    POST /api/users/bulk-action/
    """
    BULK_ACTION_LIMIT = 500

    try:
        data = json.loads(request.body)
        user_ids = data.get('user_ids', [])
        action = data.get('action', '')

        if not user_ids:
            return JsonResponse({
                'success': False,
                'errors': {'__all__': ['No users selected.']},
            }, status=400)

        if len(user_ids) > BULK_ACTION_LIMIT:
            return JsonResponse({
                'success': False,
                'errors': {'__all__': [
                    f'Bulk actions are limited to {BULK_ACTION_LIMIT} users per request.'
                ]},
            }, status=400)

        valid_actions = [
            'deactivate', 'activate', 'force_reset',
            'enable_2fa', 'disable_2fa',
        ]
        if action not in valid_actions:
            return JsonResponse({
                'success': False,
                'errors': {'__all__': ['Invalid action.']},
            }, status=400)

        # Exclude self and filter by lower role hierarchy
        actor_weight = get_role_weight(request.user.role)
        users = User.objects.filter(id__in=user_ids).exclude(id=request.user.id)

        affected_count = 0
        sessions_revoked = 0
        skipped = 0

        for user in users:
            # RBAC: Only affect users below the actor's role
            if get_role_weight(user.role) > actor_weight:
                skipped += 1
                continue

            if action == 'deactivate' and user.is_active:
                user.is_active = False
                
                # Auto-disable MFA
                if user.mfa_enabled or user.mfa_secret:
                    user.mfa_enabled = False
                    user.mfa_secret = ''
                
                user.modified_by = request.user
                user.save(update_fields=['is_active', 'mfa_enabled', 'mfa_secret', 'modified_by', 'updated_at'])
                
                active_sessions = ActiveSession.objects.filter(
                    user=user, is_active=True
                )
                sessions_revoked += active_sessions.count()
                for session in active_sessions:
                    session.revoke()
                    
                devices = DeviceAuthorization.objects.filter(user=user, status='APPROVED')
                sessions_revoked += devices.count()
                devices.update(status='REVOKED')
                    
                affected_count += 1

            elif action == 'activate' and not user.is_active:
                user.is_active = True
                user.modified_by = request.user
                user.save(update_fields=['is_active', 'modified_by', 'updated_at'])
                affected_count += 1

            elif action == 'force_reset':
                user.password_change_required = True
                user.modified_by = request.user
                user.save(update_fields=[
                    'password_change_required', 'modified_by', 'updated_at'
                ])
                affected_count += 1

            elif action == 'enable_2fa' and not user.mfa_enabled:
                user.mfa_enabled = True
                user.modified_by = request.user
                user.save(update_fields=['mfa_enabled', 'modified_by', 'updated_at'])
                affected_count += 1

            elif action == 'disable_2fa' and user.mfa_enabled:
                user.mfa_enabled = False
                user.modified_by = request.user
                user.save(update_fields=['mfa_enabled', 'modified_by', 'updated_at'])
                affected_count += 1

        action_display = action.replace('_', ' ').title()
        details = f"Bulk action '{action_display}': {affected_count} affected"
        if skipped > 0:
            details += f", {skipped} skipped (insufficient privileges)"
        if sessions_revoked > 0:
            details += f", {sessions_revoked} sessions revoked"

        AuditLog.log(
            action='BULK_ACTION',
            user=request.user,
            details=details,
            ip_address=_get_client_ip(request),
        )

        return JsonResponse({
            'success': True,
            'affected_count': affected_count,
            'skipped': skipped,
            'sessions_revoked': sessions_revoked,
            'message': f"Successfully {action.replace('_', ' ')}d {affected_count} users",
        })

    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'errors': {'__all__': ['Invalid JSON body.']},
        }, status=400)
    except Exception as e:
        logger.error(f"Error performing bulk action: {e}")
        return JsonResponse({
            'success': False,
            'errors': {'__all__': ['An unexpected error occurred.']},
        }, status=500)


# ======================================================================
# Search Users (with updated_at for optimistic locking)
# ======================================================================

@require_GET
@admin_required
def search_users(request):
    """
    Search and filter users. Includes updated_at for optimistic locking.
    GET /api/users/search/?q=<query>&status=active|disabled&page=1
    """
    try:
        query = request.GET.get('q', '').strip()
        status_filter = request.GET.get('status', 'active')
        page = int(request.GET.get('page', 1))
        per_page = 20

        users = User.objects.filter(organization=request.user.organization)

        if status_filter == 'active':
            users = users.filter(is_active=True)
        elif status_filter == 'disabled':
            users = users.filter(is_active=False)

        if query:
            users = users.filter(
                Q(first_name__icontains=query) |
                Q(last_name__icontains=query) |
                Q(email__icontains=query)
            )

        users = users.order_by('first_name', 'last_name', 'email')

        total = users.count()
        start = (page - 1) * per_page
        end = start + per_page
        users_page = users[start:end]

        user_list = []
        for user in users_page:
            user_list.append({
                'id': str(user.id),
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'full_name': user.full_name,
                'role': user.role,
                'role_display': user.get_role_display(),
                'department': user.department or '-',
                'is_active': user.is_active,
                'mfa_enabled': user.mfa_enabled,
                'totp_configured': bool(user.mfa_secret),
                'security_score': user.security_score,
                'expires_at': (
                    user.expires_at.isoformat() if user.expires_at else None
                ),
                'last_login': (
                    user.last_login.isoformat() if user.last_login else None
                ),
                'password_change_required': user.password_change_required,
                'updated_at': user.updated_at.isoformat(),
            })

        return JsonResponse({
            'success': True,
            'users': user_list,
            'total': total,
            'page': page,
            'per_page': per_page,
            'has_next': end < total,
            'has_prev': page > 1,
        })

    except Exception as e:
        logger.error(f"Error searching users: {e}")
        return JsonResponse({
            'success': False,
            'errors': {'__all__': [str(e)]},
        }, status=500)


# ======================================================================
# Update User Info (Hardened with RBAC + Optimistic Locking)
# ======================================================================

@require_POST
@csrf_protect
@admin_required
def update_user_info(request, user_id):
    """
    Update basic user information with RBAC + optimistic locking.
    POST /api/users/<uuid>/update-info/
    """
    try:
        target_user = User.objects.get(
            id=user_id, organization=request.user.organization
        )

        # 0.5A: RBAC hierarchy
        rbac_error = enforce_role_hierarchy(request.user, target_user)
        if rbac_error:
            return rbac_error

        data = json.loads(request.body)

        # 0.5C: Optimistic locking
        lock_error = check_optimistic_lock(
            target_user, data.get('updated_at', '')
        )
        if lock_error:
            return lock_error

        # Update allowed fields
        if 'first_name' in data:
            target_user.first_name = data['first_name'].strip()[:100]
        if 'last_name' in data:
            target_user.last_name = data['last_name'].strip()[:100]
        if 'department' in data:
            target_user.department = data['department'].strip()[:100]

        # 0.5D: Role assignment validation
        if 'role' in data:
            new_role = data['role']
            if new_role in dict(User.ROLE_CHOICES):
                role_error = validate_role_assignment(request.user, new_role)
                if role_error:
                    return role_error
                target_user.role = new_role

        target_user.modified_by = request.user
        target_user.save()

        AuditLog.log(
            action='USER_UPDATED',
            user=request.user,
            details=f"Updated profile for {target_user.email}",
            ip_address=_get_client_ip(request),
            related_object=target_user,
        )

        return JsonResponse({
            'success': True,
            'updated_at': target_user.updated_at.isoformat(),
            'message': f"Updated profile for {target_user.email}",
        })

    except User.DoesNotExist:
        return JsonResponse({
            'success': False,
            'errors': {'__all__': ['User not found.']},
        }, status=404)
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'errors': {'__all__': ['Invalid JSON body.']},
        }, status=400)
    except Exception as e:
        logger.error(f"Error updating user info: {e}")
        return JsonResponse({
            'success': False,
            'errors': {'__all__': ['An unexpected error occurred.']},
        }, status=500)


# ======================================================================
# User Details API (for side-drawer)
# ======================================================================

@require_GET
@admin_required
def get_user_details(request, user_id):
    """
    Get full user details for the side-drawer.
    GET /api/users/<uuid>/details/
    """
    try:
        user = User.objects.get(
            id=user_id, organization=request.user.organization
        )

        return JsonResponse({
            'success': True,
            'user': {
                'id': str(user.id),
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'full_name': user.full_name,
                'role': user.role,
                'role_display': user.get_role_display(),
                'department': user.department or '',
                'is_active': user.is_active,
                'mfa_enabled': user.mfa_enabled,
                'totp_configured': bool(user.mfa_secret),
                'two_factor_method': user.two_factor_method,
                'security_score': user.security_score,
                'expires_at': (
                    user.expires_at.isoformat() if user.expires_at else None
                ),
                'extension_requested': user.extension_requested,
                'extension_request_message': user.extension_request_message,
                'extension_request_status': user.extension_request_status,
                'extension_request_status_display': user.get_extension_request_status_display() if user.extension_request_status else '',
                'last_login': (
                    user.last_login.isoformat() if user.last_login else None
                ),
                'created_at': user.created_at.isoformat(),
                'updated_at': user.updated_at.isoformat(),
                'password_change_required': user.password_change_required,
                'is_expired': user.is_expired,
                'can_edit': can_modify_user(request.user, user),
            },
        })

    except User.DoesNotExist:
        return JsonResponse({
            'success': False,
            'errors': {'__all__': ['User not found.']},
        }, status=404)


# ======================================================================
# Session Heartbeat (4.x — Active Session Lifecycle)
# ======================================================================

from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
@require_http_methods(['POST'])
def session_heartbeat(request):
    """
    Desktop agent heartbeat endpoint (4.x).

    Called by the desktop app every N minutes to signal the session is alive.
    Updates `last_activity` on the matching ActiveSession record.

    The desktop app must include the Authorization header:
        Authorization: Bearer <jwt_token>

    If the session has been revoked by an admin, returns 401 so the
    desktop app knows to disconnect.

    POST /api/sessions/heartbeat/
    Returns: { "alive": true } or 401 if revoked/not found
    """
    from .services import SessionService

    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if not auth_header.startswith('Bearer '):
        return JsonResponse({'alive': False, 'error': 'Missing token'}, status=401)

    jwt_token = auth_header.split(' ', 1)[1]

    try:
        # Decode JWT to get jti claim
        import jwt as pyjwt
        from django.conf import settings

        payload = pyjwt.decode(
            jwt_token,
            settings.SECRET_KEY,
            algorithms=['HS256'],
            options={'verify_exp': False}  # We handle expiry ourselves via session state
        )
        jti = payload.get('jti')

        if not jti:
            return JsonResponse({'alive': False, 'error': 'Invalid token'}, status=401)

        session = ActiveSession.objects.get(jwt_jti=jti, is_active=True)
        # Touch last_activity (auto_now=True on the field will update on save)
        session.save(update_fields=['last_activity'])

        # Opportunistically clean up stale sessions on each heartbeat
        ActiveSession.cleanup_stale(stale_minutes=30)

        return JsonResponse({
            'alive': True,
            'session_id': str(session.id),
            'last_activity': session.last_activity.isoformat(),
        })

    except ActiveSession.DoesNotExist:
        return JsonResponse({'alive': False, 'error': 'Session revoked or not found'}, status=401)
    except Exception as e:
        logger.error(f"Heartbeat error: {e}")
        return JsonResponse({'alive': False, 'error': 'Internal error'}, status=500)


@require_GET
@admin_required
def cleanup_stale_sessions(request):
    """
    Manual trigger for stale session cleanup (admin only).
    GET /api/sessions/cleanup/
    """
    try:
        stale_minutes = int(request.GET.get('stale_minutes', 30))
        count = ActiveSession.cleanup_stale(stale_minutes=stale_minutes)
        expired_count = ActiveSession.cleanup_expired(max_age_hours=24)

        AuditLog.log(
            action='SESSIONS_CLEANED',
            user=request.user,
            details=f"Manual cleanup: {count} stale + {expired_count} expired sessions revoked",
            ip_address=_get_client_ip(request),
        )

        return JsonResponse({
            'success': True,
            'stale_revoked': count,
            'expired_revoked': expired_count,
            'message': f"Revoked {count} stale and {expired_count} expired sessions.",
        })
    except Exception as e:
        logger.error(f"Session cleanup error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)
