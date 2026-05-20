"""
AVAGuard Web Portal - Cross-Cutting Security Layer (Phase 0.5)

Enterprise-grade security primitives:
- RBAC hierarchy enforcement (prevents privilege escalation)
- Sudo-mode re-authentication (server-side timestamp validation)
- Optimistic locking (prevents silent overwrites via 409 Conflict)
- Role hierarchy constants

These utilities are consumed by views and middleware. They are NOT
UI-level guards — they enforce invariants at the backend regardless
of how the request is constructed.
"""

import functools
import logging
from datetime import timedelta

from django.http import JsonResponse
from django.utils import timezone

logger = logging.getLogger(__name__)

# ======================================================================
# ROLE HIERARCHY — Numeric weight determines permission level.
# Higher weight = more privilege. Used for comparison checks.
# ======================================================================
ROLE_HIERARCHY = {
    'SUPER_ADMIN': 100,
    'IT_ADMIN': 75,
    'AUDITOR': 50,
    'VIEWER': 25,
}

# Sudo-mode validity window (seconds)
SUDO_VALIDITY_SECONDS = 300  # 5 minutes


def get_role_weight(role: str) -> int:
    """Return the numeric weight for a role string. Unknown roles get 0."""
    return ROLE_HIERARCHY.get(role, 0)


# ======================================================================
# 0.5A — RBAC HIERARCHY ENFORCEMENT
# ======================================================================

def can_modify_user(actor, target) -> bool:
    """
    Check if `actor` is allowed to modify `target`.

    Rules:
    1. Actor must have strictly higher role weight than target.
    2. Users cannot modify their own privilege-related fields.
    3. Only SUPER_ADMIN can modify IT_ADMIN or AUDITOR.
    """
    actor_weight = get_role_weight(actor.role)
    target_weight = get_role_weight(target.role)

    # Actor can modify target if their role weight is greater than or equal to target's role weight.
    # Self-modification is checked before this function.
    if actor_weight >= target_weight:
        return True

    return False


def enforce_role_hierarchy(actor, target):
    """
    Raise a structured error dict if `actor` cannot modify `target`.
    Returns None on success; returns a JsonResponse on failure.
    """
    if actor.pk == target.pk:
        return JsonResponse({
            'success': False,
            'errors': {'__all__': ['You cannot modify your own account through admin controls.']},
        }, status=403)

    if not can_modify_user(actor, target):
        logger.warning(
            f"Privilege escalation blocked: {actor.email} (role={actor.role}) "
            f"attempted to modify {target.email} (role={target.role})"
        )
        return JsonResponse({
            'success': False,
            'errors': {'__all__': [
                'Insufficient privileges. You cannot modify users with a higher role.'
            ]},
        }, status=403)

    return None  # Access granted


# ======================================================================
# 0.5B — SUDO-MODE ENFORCEMENT
# ======================================================================

def is_sudo_valid(request) -> bool:
    """Check if the current session has a valid sudo-mode timestamp."""
    confirmed_at = request.session.get('sudo_confirmed_at')
    if not confirmed_at:
        return False

    try:
        confirmed_time = timezone.datetime.fromisoformat(confirmed_at)
        if timezone.is_naive(confirmed_time):
            confirmed_time = timezone.make_aware(confirmed_time)
        elapsed = timezone.now() - confirmed_time
        return elapsed.total_seconds() <= SUDO_VALIDITY_SECONDS
    except (ValueError, TypeError):
        return False


def set_sudo_timestamp(request):
    """Mark the current session as sudo-confirmed right now."""
    request.session['sudo_confirmed_at'] = timezone.now().isoformat()


def clear_sudo_timestamp(request):
    """Invalidate sudo-mode for the current session."""
    request.session.pop('sudo_confirmed_at', None)


def sudo_required(view_func):
    """
    Decorator: requires sudo-mode (re-authentication within 5 minutes)
    before allowing the view to execute.

    Returns 403 JSON with 'sudo_required': True so the frontend
    can prompt for re-authentication.
    """
    @functools.wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not is_sudo_valid(request):
            return JsonResponse({
                'success': False,
                'sudo_required': True,
                'errors': {'__all__': [
                    'This action requires re-authentication. '
                    'Please confirm your password to continue.'
                ]},
            }, status=403)
        return view_func(request, *args, **kwargs)
    return wrapper


# ======================================================================
# 0.5C — OPTIMISTIC LOCKING
# ======================================================================

def check_optimistic_lock(instance, submitted_timestamp_str: str):
    """
    Compare the instance's `updated_at` against the submitted timestamp.

    Args:
        instance: Django model instance with `updated_at` field.
        submitted_timestamp_str: ISO format string of the expected `updated_at`.

    Returns:
        None on success; JsonResponse(409) on conflict.
    """
    if not submitted_timestamp_str:
        # If no timestamp submitted, skip check (backwards compatibility)
        return None

    try:
        submitted_ts = timezone.datetime.fromisoformat(submitted_timestamp_str)
        if timezone.is_naive(submitted_ts):
            submitted_ts = timezone.make_aware(submitted_ts)
    except (ValueError, TypeError):
        return JsonResponse({
            'success': False,
            'errors': {'__all__': ['Invalid timestamp format for concurrency check.']},
        }, status=400)

    # Compare with microsecond tolerance
    db_ts = instance.updated_at
    if abs((db_ts - submitted_ts).total_seconds()) > 1.0:
        return JsonResponse({
            'success': False,
            'conflict': True,
            'errors': {'__all__': [
                'This record was modified by another user. '
                'Please refresh and try again.'
            ]},
            'server_updated_at': db_ts.isoformat(),
        }, status=409)

    return None  # No conflict


# ======================================================================
# 0.5D — ROLE VALIDATION FOR ASSIGNMENT
# ======================================================================

def validate_role_assignment(actor, new_role: str):
    """
    Ensure `actor` cannot assign a role equal to or higher than their own.
    Returns None on success; JsonResponse(403) on violation.
    """
    actor_weight = get_role_weight(actor.role)
    new_weight = get_role_weight(new_role)

    if new_weight > actor_weight:
        return JsonResponse({
            'success': False,
            'errors': {'role': [
                f'You cannot assign the "{new_role}" role. '
                f'You can only assign roles at or below your own level.'
            ]},
        }, status=403)

    return None
