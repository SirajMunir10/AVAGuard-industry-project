from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from datetime import timedelta
from django.http import HttpResponseForbidden
from .models import User, AuditLog
from .admin_views import role_required

@login_required
@role_required('SUPER_ADMIN', 'IT_ADMIN')
def notifications_view(request):
    """
    Dedicated notifications page (Bug 4).
    Shows extension requests and system alerts based on role.
    """
    context = {
        'active_page': 'notifications',
        'extension_requests': [],
        'system_alerts': []
    }
    
    # Super Admin sees extension requests and alerts
    if request.user.role == 'SUPER_ADMIN':
        context['extension_requests'] = User.objects.filter(
            extension_requested=True,
            extension_request_status='PENDING'
        )
        
    # IT Admin and Super Admin see failed login alerts
    yesterday = timezone.now() - timedelta(hours=24)
    context['system_alerts'] = AuditLog.objects.filter(
        action__icontains='FAIL',
        timestamp__gte=yesterday
    ).select_related('user').order_by('-timestamp')[:50]
    
    return render(request, 'dashboard/notifications.html', context)

@login_required
@role_required('SUPER_ADMIN')
def approve_extension(request, notification_id):
    """Approve an extension request."""
    if request.method == 'POST':
        user = get_object_or_404(User, id=notification_id)
        
        # Extend by 30 days
        if user.expires_at:
            user.expires_at = user.expires_at + timedelta(days=30)
        else:
            user.expires_at = timezone.now() + timedelta(days=30)
            
        user.extension_request_status = 'APPROVED'
        user.extension_requested = False
        user.save(update_fields=['expires_at', 'extension_request_status', 'extension_requested'])
        
        AuditLog.log(
            action='ACCOUNT_EXTENDED',
            user=user,
            details=f"Extension request approved by {request.user.email}"
        )
        messages.success(request, f"Extension approved for {user.email}.")
        
    return redirect('notifications')

@login_required
@role_required('SUPER_ADMIN')
def deny_extension(request, notification_id):
    """Deny an extension request."""
    if request.method == 'POST':
        user = get_object_or_404(User, id=notification_id)
        
        user.extension_request_status = 'DENIED'
        user.extension_requested = False
        user.save(update_fields=['extension_request_status', 'extension_requested'])
        
        AuditLog.log(
            action='ACCOUNT_EXTENSION_DENIED',
            user=user,
            details=f"Extension request denied by {request.user.email}"
        )
        messages.warning(request, f"Extension denied for {user.email}.")
        
    return redirect('notifications')
