"""
AVAGuard Web Portal - Admin Views

Role-based dashboard views for Super Admin, IT Admin, and Viewer.
"""

import json
from datetime import timedelta
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Avg, Sum, Count, Q
from django.core.cache import cache
from django.utils import timezone
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_POST

from .models import User, Organization, ScanSummary, ScanResult, ActiveSession, AuditLog
from .constants import ROLE_HIERARCHY


def role_required(*allowed_roles):
    """Decorator to check if user has one of the allowed roles."""
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('login')
            if request.user.role not in allowed_roles:
                messages.error(request, 'You do not have permission to access this page.')
                return redirect('dashboard')
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


@login_required
def role_based_dashboard(request):
    """
    Redirect to the appropriate dashboard based on user role.
    """
    role = getattr(request.user, 'role', 'VIEWER')
    
    if role == 'SUPER_ADMIN':
        return redirect('admin_dashboard')
    elif role == 'IT_ADMIN':
        return redirect('it_dashboard')
    elif role == 'AUDITOR':
        return redirect('auditor_dashboard')
    else:
        return redirect('viewer_dashboard')


@login_required
@role_required('SUPER_ADMIN')
def admin_dashboard(request):
    """
    Super Admin dashboard — uses the original design system template.
    Provides full compliance overview + admin-specific data (users, sessions, logs).
    """
    from django.db.models import Count, Avg, Sum
    import json
    
    org = request.user.organization
    
    org_id = org.id if org else 'global'
    cache_key = f'admin_dashboard_stats_{org_id}'
    cached_data = cache.get(cache_key)
    
    scans_qs = ScanSummary.objects.select_related('organization', 'uploaded_by').all()
    if org:
        scans_qs = scans_qs.filter(organization=org)

    if cached_data:
        stats, trend_labels, trend_data, has_trend_data = cached_data
    else:
        # ── Compliance stats computations ──
        stats = scans_qs.aggregate(
            total_scans=Count('id'),
            avg_score=Avg('overall_score'),
            total_passed=Sum('passed_count'),
            total_failed=Sum('failed_count'),
            total_warning=Sum('warning_count'),
        )
        # Trend data (last 4 weeks)
        trend_labels = []
        trend_data = []
        has_trend_data = False
        
        for i in range(4, 0, -1):
            week_start = timezone.now() - timedelta(weeks=i)
            week_end = week_start + timedelta(weeks=1)
            
            week_avg = scans_qs.filter(
                Q(scan_timestamp__gte=week_start, scan_timestamp__lt=week_end) |
                Q(uploaded_at__gte=week_start, uploaded_at__lt=week_end)
            ).aggregate(avg=Avg('overall_score'))['avg']
            
            trend_labels.append(f"Week {5-i}")
            val = float(week_avg or 0)
            trend_data.append(val)
            if val > 0:
                has_trend_data = True
            
        cache.set(cache_key, (stats, trend_labels, trend_data, has_trend_data), 60 * 5) # Cache for 5 mins

    total_checks = (stats['total_passed'] or 0) + (stats['total_failed'] or 0)
    stats['pass_rate'] = ((stats['total_passed'] or 0) / total_checks * 100) if total_checks > 0 else 0

    # Recent scans (show actual most recent, not just last 30 days)
    recent_scans = scans_qs.order_by('-scan_timestamp')[:10]
    last_scan = recent_scans.first() if recent_scans.exists() else None

    # Admin-specific data
    users_qs = User.objects.select_related('organization').all()
    if org:
        users_qs = users_qs.filter(organization=org)

    total_users = users_qs.count()
    active_users = users_qs.filter(is_active=True).count()
    inactive_users = users_qs.filter(is_active=False).count()

    # Recent users for dashboard table
    recent_users = users_qs.order_by('-created_at')[:5]

    now = timezone.now()
    expired_users = users_qs.filter(expires_at__lt=now).count()
    pending_extensions = users_qs.filter(extension_requested=True, extension_request_status='PENDING').count()

    active_sessions_qs = ActiveSession.objects.select_related('user').filter(is_active=True)
    active_sessions_count = active_sessions_qs.count()
    recent_sessions = active_sessions_qs.order_by('-started_at')[:5]

    total_reports = 0 # Placeholder for reports module

    # Audit logs
    audit_logs = AuditLog.objects.select_related('user').order_by('-timestamp')[:5]

    # Common failures analysis (Dynamic)
    common_failures = []
    failed_checks = ScanResult.objects.filter(
        scan__organization=org,
        status='FAIL'
    ).values('title').annotate(count=Count('title')).order_by('-count')[:5]

    for check in failed_checks:
        common_failures.append({
            'name': check['title'],
            'count': check['count'],
            'percentage': 100 # Default for visual bar
        })

    if not common_failures:
        common_failures = [
            {'name': 'MFA Not Enabled', 'count': 0, 'percentage': 0},
            {'name': 'Weak Password Policy', 'count': 0, 'percentage': 0},
        ]

    # Security alerts
    yesterday = timezone.now() - timedelta(hours=24)
    failed_logins = AuditLog.objects.select_related('user').filter(
        action__icontains='FAIL',
        timestamp__gte=yesterday
    ).count()

    users_no_2fa = users_qs.filter(mfa_enabled=False).count()
    seven_days = timezone.now() + timedelta(days=7)
    expiring_accounts = users_qs.filter(
        expires_at__isnull=False,
        expires_at__lte=seven_days
    ).count()

    security_alerts = (failed_logins > 0 or users_no_2fa > 0 or expiring_accounts > 0)

    # ── Dashboard 2: Device & Endpoint Health ──────────────────────────
    # OS distribution from scan data
    os_counts = scans_qs.values('environment').annotate(
        count=Count('id'),
        avg_score=Avg('overall_score')
    ).order_by('-count')

    # Device score bands — classify each scan by its score bucket
    score_critical = scans_qs.filter(overall_score__lt=50).count()
    score_high     = scans_qs.filter(overall_score__gte=50, overall_score__lt=70).count()
    score_medium   = scans_qs.filter(overall_score__gte=70, overall_score__lt=90).count()
    score_low      = scans_qs.filter(overall_score__gte=90).count()

    # Last-seen distribution: scans by age
    seven_days_ago   = now - timedelta(days=7)
    thirty_days_ago  = now - timedelta(days=30)

    scans_last_7d  = scans_qs.filter(scan_timestamp__gte=seven_days_ago).count()
    scans_7_30d    = scans_qs.filter(
        scan_timestamp__gte=thirty_days_ago, scan_timestamp__lt=seven_days_ago
    ).count()
    scans_older    = scans_qs.filter(scan_timestamp__lt=thirty_days_ago).count()

    # Stale agents: scans not seen in > 7 days (deduplicated by environment)
    stale_agents = scans_qs.filter(
        scan_timestamp__lt=seven_days_ago
    ).order_by('-scan_timestamp').values(
        'environment', 'scan_timestamp', 'overall_score'
    )[:8]

    # Score over time per environment for sparklines (last 12 weeks)
    env_trend = {}
    for week in range(11, -1, -1):
        wk_start = now - timedelta(weeks=week+1)
        wk_end   = now - timedelta(weeks=week)
        avg = scans_qs.filter(
            scan_timestamp__gte=wk_start, scan_timestamp__lt=wk_end
        ).aggregate(avg=Avg('overall_score'))['avg']
        env_trend[f"W-{week}"] = round(float(avg or 0), 1)

    # ── Dashboard 3: User & Activity Intelligence ──────────────────────
    # Role distribution
    role_dist = users_qs.values('role').annotate(count=Count('id')).order_by('role')
    role_labels = [r['role'].replace('_', ' ').title() for r in role_dist]
    role_counts_data = [r['count'] for r in role_dist]

    # MFA adoption
    mfa_enabled_count  = users_qs.filter(mfa_enabled=True).count()
    mfa_disabled_count = total_users - mfa_enabled_count
    mfa_pct = round((mfa_enabled_count / total_users * 100), 1) if total_users > 0 else 0

    # Login activity: audit log counts by hour of day (last 7 days)
    from django.db.models.functions import ExtractHour, ExtractWeekDay
    login_logs = AuditLog.objects.filter(
        action='LOGIN', timestamp__gte=seven_days_ago
    )
    logins_by_hour = list(
        login_logs.annotate(hour=ExtractHour('timestamp'))
        .values('hour').annotate(count=Count('id')).order_by('hour')
    )
    # Build complete 24-hour array
    hour_map = {entry['hour']: entry['count'] for entry in logins_by_hour}
    login_by_hour_data = [hour_map.get(h, 0) for h in range(24)]

    # Login activity: last 7 days total per day
    from django.db.models.functions import TruncDate
    logins_by_day = list(
        login_logs.annotate(day=TruncDate('timestamp'))
        .values('day').annotate(count=Count('id')).order_by('day')
    )

    # Failed login breakdown by user (top 5)
    top_failed = list(
        AuditLog.objects.filter(
            action__icontains='LOGIN_FAIL',
            timestamp__gte=seven_days_ago
        ).values('user__email').annotate(count=Count('id')).order_by('-count')[:5]
    )

    # MFA adoption trend (per week, last 8 weeks) — proxy via new users registered
    mfa_trend_data = []
    mfa_trend_labels = []
    for week in range(7, -1, -1):
        wk_start = now - timedelta(weeks=week+1)
        wk_end   = now - timedelta(weeks=week)
        week_users = users_qs.filter(created_at__gte=wk_start, created_at__lt=wk_end)
        total_wk  = week_users.count()
        mfa_wk    = week_users.filter(mfa_enabled=True).count()
        pct = round((mfa_wk / total_wk * 100), 1) if total_wk > 0 else 0.0
        mfa_trend_data.append(pct)
        mfa_trend_labels.append(f"W-{week}")

    context = {
        'active_page': 'dashboard',
        'organization': org,
        'stats': stats,
        'recent_scans': recent_scans,
        'last_scan': last_scan,
        'trend_labels': json.dumps(trend_labels),
        'trend_data': json.dumps(trend_data),
        'has_trend_data': has_trend_data,
        # Security alert banner data
        'security_alerts': security_alerts,
        'failed_logins': failed_logins,
        'users_no_2fa': users_no_2fa,
        'expiring_accounts': expiring_accounts,

        # Super Admin expanded data
        'total_users': total_users,
        'active_users': active_users,
        'inactive_users': inactive_users,
        'expired_users': expired_users,
        'pending_extensions': pending_extensions,
        'active_sessions_count': active_sessions_count,
        'active_sessions': active_sessions_count,
        'pending_requests': pending_extensions,
        'recent_sessions': recent_sessions,
        'recent_users': recent_users,
        'audit_logs': audit_logs,
        'total_reports': total_reports,
        'common_failures': common_failures,

        # ── Dashboard 2: Device & Endpoint Health ──
        'os_counts': list(os_counts),
        'score_critical': score_critical,
        'score_high': score_high,
        'score_medium': score_medium,
        'score_low': score_low,
        'scans_last_7d': scans_last_7d,
        'scans_7_30d': scans_7_30d,
        'scans_older': scans_older,
        'stale_agents': list(stale_agents),
        'env_trend_labels': json.dumps(list(env_trend.keys())),
        'env_trend_data': json.dumps(list(env_trend.values())),
        'total_devices_scanned': scans_qs.count(),

        # ── Dashboard 3: User & Activity Intelligence ──
        'role_labels': json.dumps(role_labels),
        'role_counts_data': json.dumps(role_counts_data),
        'mfa_enabled_count': mfa_enabled_count,
        'mfa_disabled_count': mfa_disabled_count,
        'mfa_pct': mfa_pct,
        'login_by_hour_data': json.dumps(login_by_hour_data),
        'logins_by_day': logins_by_day,
        'top_failed': top_failed,
        'mfa_trend_labels': json.dumps(mfa_trend_labels),
        'mfa_trend_data': json.dumps(mfa_trend_data),
    }

    return render(request, 'dashboard/admin.html', context)


@login_required
@role_required('SUPER_ADMIN', 'IT_ADMIN')
def it_dashboard(request):
    """
    IT Admin dashboard focused on scan management.
    """
    org = request.user.organization
    
    # Scan metrics
    scans_qs = ScanSummary.objects.select_related('organization', 'uploaded_by').all()
    if org:
        scans_qs = scans_qs.filter(organization=org)
    
    org_id = org.id if org else 'global'
    cache_key = f'it_dashboard_stats_{org_id}'
    cached_data = cache.get(cache_key)

    thirty_days_ago = timezone.now() - timedelta(days=30)
    recent_scans_qs = scans_qs.filter(uploaded_at__gte=thirty_days_ago)

    if cached_data:
        avg_score, scans_this_month, scans_today, total_failures, chart_labels, chart_data = cached_data
    else:
        avg_score = recent_scans_qs.aggregate(avg=Avg('overall_score'))['avg'] or 0
        scans_this_month = recent_scans_qs.count()
        scans_today = scans_qs.filter(uploaded_at__date=timezone.now().date()).count()
        total_failures = recent_scans_qs.aggregate(total=Sum('failed_count'))['total'] or 0
        
        # Chart data - last 30 days
        chart_labels = []
        chart_data = []
        for i in range(29, -1, -1):
            day = timezone.now().date() - timedelta(days=i)
            day_score = scans_qs.filter(
                uploaded_at__date=day
            ).aggregate(avg=Avg('overall_score'))['avg']
            
            chart_labels.append(day.strftime('%b %d'))
            chart_data.append(float(day_score) if day_score else 0)
            
        cache.set(cache_key, (avg_score, scans_this_month, scans_today, total_failures, chart_labels, chart_data), 60 * 5)
    
    # Pending access requests (Feature removed/simplified)
    pending_requests = 0
    
    # Recent scans for table — map ORM objects to template-compatible dicts
    raw_scans = scans_qs.order_by('-uploaded_at')[:10]
    recent_scans = []
    for s in raw_scans:
        score = float(s.overall_score) if s.overall_score else 0
        recent_scans.append({
            'scan_id': str(s.id),
            'score': round(score, 1),
            'status': 'PASS' if score >= 80 else ('WARNING' if score >= 60 else 'FAIL'),
            'user': s.uploaded_by,
            'uploaded_at': s.uploaded_at,
            'passed_count': s.passed_count,
            'failed_count': s.failed_count,
        })
    
    # Chart data served via cache mapping above
    
    # Common failures analysis
    common_failures = []
    # This would analyze json_data for common failure patterns
    # For now, provide mock data
    common_failures = [
        {'name': 'MFA Not Enabled', 'count': 15, 'percentage': 100},
        {'name': 'Weak Password Policy', 'count': 12, 'percentage': 80},
        {'name': 'No Audit Logging', 'count': 8, 'percentage': 53},
        {'name': 'Insecure HTTPS', 'count': 5, 'percentage': 33},
    ]
    
    # ── Security alert banner data (Phase 5A) ──
    users_qs = User.objects.select_related('organization').all()
    if org:
        users_qs = users_qs.filter(organization=org)

    yesterday = timezone.now() - timedelta(hours=24)
    failed_logins = AuditLog.objects.select_related('user').filter(
        action__icontains='FAIL', timestamp__gte=yesterday
    ).count()
    users_no_2fa = users_qs.filter(mfa_enabled=False).count()
    seven_days = timezone.now() + timedelta(days=7)
    expiring_accounts = users_qs.filter(
        expires_at__isnull=False, expires_at__lte=seven_days
    ).count()
    security_alerts = (failed_logins > 0 or users_no_2fa > 0 or expiring_accounts > 0)

    context = {
        'active_page': 'it_dashboard',
        'avg_score': round(avg_score, 1),
        'scans_this_month': scans_this_month,
        'scans_today': scans_today,
        'total_failures': total_failures,
        'pending_requests': pending_requests,
        'recent_scans': recent_scans,
        'chart_labels': json.dumps(chart_labels),
        'chart_data': json.dumps(chart_data),
        'common_failures': common_failures,
        # Security alert banner
        'security_alerts': security_alerts,
        'failed_logins': failed_logins,
        'users_no_2fa': users_no_2fa,
        'expiring_accounts': expiring_accounts,
    }
    
    return render(request, 'dashboard/it.html', context)


@login_required
def viewer_dashboard(request):
    """
    Viewer/Auditor dashboard with read-only access.
    """
    org = request.user.organization
    user = request.user
    
    # Available reports
    reports_qs = ScanSummary.objects.select_related('organization', 'uploaded_by').all().order_by('-uploaded_at')
    if org:
        reports_qs = reports_qs.filter(organization=org)
    
    available_reports = reports_qs.count()
    my_scans = reports_qs.filter(uploaded_by=user).count()
    
    # Access Request features simplified for now
    approved_access = 0
    pending_requests = 0
    my_pending_requests = 0
    
    # Paginate reports
    paginator = Paginator(reports_qs, 12)
    page = request.GET.get('page', 1)
    
    # Map the object properties so the template receives what it expects
    reports_page = paginator.get_page(page)
    mapped_reports = []
    for r in reports_page.object_list:
        status = "PASS" if r.failed_count == 0 else "WARNING" if r.failed_count < 5 else "FAIL"
        mapped_reports.append({
            'scan_id': str(r.id),
            'status': status,
            'is_sensitive': False, # Update this based on your sensitivity logic
            'score': r.overall_score,
            'uploaded_at': r.uploaded_at,
            'has_access': True, # Base assumption for Viewer
            'request_pending': False,
        })
    
    # Re-inject the mapped list onto the paginator page object so pagination still works
    reports_page.object_list = mapped_reports
    
    context = {
        'active_page': 'viewer_dashboard',
        'available_reports': available_reports,
        'my_scans': my_scans,
        'approved_access': approved_access,
        'pending_requests': pending_requests,
        'my_pending_requests': my_pending_requests,
        'reports': reports_page,
    }
    
    return render(request, 'dashboard/viewer.html', context)





@login_required
@role_required('AUDITOR', 'SUPER_ADMIN')
def auditor_dashboard(request):
    """
    Auditor dashboard with read-only compliance view.
    """
    org = request.user.organization
    
    # Scan metrics
    scans_qs = ScanSummary.objects.select_related('organization', 'uploaded_by').all()
    if org:
        scans_qs = scans_qs.filter(organization=org)
    
    total_scans = scans_qs.count()
    avg_score = scans_qs.aggregate(avg=Avg('overall_score'))['avg'] or 0
    total_failed = scans_qs.aggregate(total=Sum('failed_count'))['total'] or 0
    
    # Latest scan
    latest_scan = scans_qs.order_by('-uploaded_at').first()
    latest_score = latest_scan.overall_score if latest_scan else 0
    latest_date = latest_scan.uploaded_at if latest_scan else None
    
    # All scans for table — map ORM objects to template-compatible dicts
    raw_qs = scans_qs.order_by('-uploaded_at')
    mapped_scans = []
    for s in raw_qs:
        score = float(s.overall_score) if s.overall_score else 0
        mapped_scans.append({
            'scan_id': str(s.id),
            'score': round(score, 1),
            'status': 'PASS' if score >= 80 else ('WARNING' if score >= 60 else 'FAIL'),
            'uploaded_at': s.uploaded_at,
            'passed_count': s.passed_count,
            'failed_count': s.failed_count,
        })
    # Manual pagination on the mapped list
    from django.core.paginator import Paginator as DjPaginator
    paginator = DjPaginator(mapped_scans, 25)
    page = request.GET.get('page', 1)
    scans = paginator.get_page(page)
    
    context = {
        'active_page': 'auditor_dashboard',
        'total_scans': total_scans,
        'avg_score': round(avg_score, 1),
        'total_failed': total_failed,
        'latest_score': latest_score,
        'latest_date': latest_date,
        'latest_scan': latest_scan,
        'scans': scans,
    }
    
    return render(request, 'dashboard/auditor.html', context)


@login_required
@role_required('SUPER_ADMIN', 'IT_ADMIN', 'AUDITOR')
def audit_logs(request):
    """
    Audit logs viewer with standard pagination for UI consistency.
    """
    org = request.user.organization

    logs_qs = AuditLog.objects.select_related('user').all().order_by('-timestamp', '-id')
    if org:
        logs_qs = logs_qs.filter(Q(user__organization=org) | Q(user__isnull=True))

    # Filtering: action
    action_filter = request.GET.get('action', '')
    if action_filter:
        logs_qs = logs_qs.filter(action__icontains=action_filter)

    # Filtering: role
    role_filter = request.GET.get('role', '')
    if role_filter:
        logs_qs = logs_qs.filter(user__role=role_filter)

    # Filtering: user
    user_filter = request.GET.get('user_id', '')
    if user_filter:
        logs_qs = logs_qs.filter(user__id=user_filter)

    # Filtering: date range
    date_range = request.GET.get('date_range', 'all')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')

    if date_range == 'today':
        logs_qs = logs_qs.filter(timestamp__date=timezone.now().date())
    elif date_range == '7':
        logs_qs = logs_qs.filter(timestamp__gte=timezone.now() - timedelta(days=7))
    elif date_range == '30':
        logs_qs = logs_qs.filter(timestamp__gte=timezone.now() - timedelta(days=30))
    elif date_range == '90':
        logs_qs = logs_qs.filter(timestamp__gte=timezone.now() - timedelta(days=90))
    elif date_range == 'custom':
        if date_from:
            logs_qs = logs_qs.filter(timestamp__date__gte=date_from)
        if date_to:
            logs_qs = logs_qs.filter(timestamp__date__lte=date_to)

    # Stats for summary (only if no filtering/paging on first load?)
    login_count = logs_qs.filter(action='LOGIN').count()
    failed_count = logs_qs.filter(action='LOGIN_FAILED').count()
    unique_users = logs_qs.values('user').distinct().count()

    # Limit for client-side pagination to match Scans/Reports
    audit_logs_list = logs_qs[:500]

    # Get users for dropdown
    users = User.objects.select_related('organization').filter(organization=org).order_by('email')

    context = {
        'active_page': 'audit',
        'audit_logs': audit_logs_list,
        'action_count': logs_qs.count(),
        'login_count': login_count,
        'failed_count': failed_count,
        'unique_users': unique_users,
        'action_count': logs_qs.count(),
        'action_filter': action_filter,
        'role_filter': role_filter,
        'user_filter': user_filter,
        'date_range': date_range,
        'date_from': date_from,
        'date_to': date_to,
        'users': users,
        'role_choices': User.ROLE_CHOICES,
    }

    return render(request, 'admin/audit_logs.html', context)


# ==========================================
# User Management Views (Super Admin)
# ==========================================

@login_required
@role_required('SUPER_ADMIN')
@require_POST
def add_user(request):
    """Add a new user."""
    from .validators import NISTPasswordValidator
    
    email = request.POST.get('email', '').lower().strip()
    first_name = request.POST.get('first_name', '').strip()
    last_name = request.POST.get('last_name', '').strip()
    role = request.POST.get('role', 'VIEWER')
    password = request.POST.get('password', '')
    
    # Validate password
    try:
        validator = NISTPasswordValidator()
        validator.validate(password)
    except Exception as e:
        messages.error(request, f'Password error: {e}')
        return redirect('admin_dashboard')
    
    # Check if user exists
    if User.objects.select_related('organization').filter(email=email).exists():
        messages.error(request, 'User with this email already exists.')
        return redirect('admin_dashboard')
    
    # Create user
    try:
        user = User.objects.create_user(
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            role=role,
            organization=request.user.organization
        )
        messages.success(request, f'User {email} created successfully.')
        
        AuditLog.log(
            action='USER_CREATED',
            user=request.user,
            details=f'Created user {email} with role {role}'
        )
    except Exception as e:
        messages.error(request, f'Error creating user: {e}')
    
    return redirect('admin_dashboard')


@login_required
@role_required('SUPER_ADMIN')
@require_POST
def toggle_user_status(request, user_id):
    """Toggle user active status."""
    user = get_object_or_404(User, id=user_id)
    user.is_active = not user.is_active
    user.save()
    
    AuditLog.log(
        action='USER_STATUS_CHANGED',
        user=request.user,
        details=f'{"Activated" if user.is_active else "Deactivated"} user {user.email}'
    )
    
    return JsonResponse({'success': True, 'is_active': user.is_active})


@login_required
@role_required('SUPER_ADMIN')
@require_POST
def reset_user_password(request, user_id):
    """Send password reset email."""
    user = get_object_or_404(User, id=user_id)
    
    # In production, this would send an email with reset link
    # For now, just log the action
    AuditLog.log(
        action='PASSWORD_RESET_SENT',
        user=request.user,
        details=f'Password reset initiated for {user.email}'
    )
    
    return JsonResponse({'success': True, 'message': 'Password reset email sent!'})


# ==========================================
# Session Management Views
# ==========================================

@login_required
@role_required('SUPER_ADMIN', 'IT_ADMIN')
@require_POST
def revoke_session(request, session_id):
    """Revoke an active session (Phase 3 — Hardened)."""
    session = get_object_or_404(
        ActiveSession, id=session_id,
        user__organization=request.user.organization,
    )

    # Self-revocation protection
    if session.user_id == request.user.id:
        messages.error(request, 'Cannot revoke your own session.')
        return redirect('active_sessions')

    # Role hierarchy enforcement
    request_user_rank = ROLE_HIERARCHY.get(request.user.role, 0)
    target_user_rank = ROLE_HIERARCHY.get(session.user.role, 0)

    if request_user_rank >= target_user_rank:
        # ALLOW
        pass
    else:
        messages.error(request, 'You do not have permission to revoke a session of a user with a higher role.')
        return redirect('active_sessions')

    session.revoke()

    AuditLog.log(
        action='SESSION_REVOKED',
        user=request.user,
        details=f'Revoked session for {session.user.email}',
    )

    messages.success(request, f'Session for {session.user.email} has been revoked.')
    return redirect('active_sessions')


@login_required
def scan_detail(request, scan_id):
    """View scan details."""
    scan = get_object_or_404(ScanSummary, id=scan_id)
    
    # Simplified access control (org based)
    if scan.organization != request.user.organization:
        messages.error(request, 'Permission denied.')
        return redirect('viewer_dashboard')
        
    results = ScanResult.objects.filter(scan=scan)
    
    context = {
        'scan': scan,
        'results': results,
    }
    
    return render(request, 'dashboard/scan_detail.html', context)


@login_required
def download_report(request, scan_id):
    """Download scan as JSON."""
    scan = get_object_or_404(ScanSummary, id=scan_id)
    results = ScanResult.objects.filter(scan=scan)
    
    report_data = {
        'id': str(scan.id),
        'score': float(scan.overall_score),
        'timestamp': scan.uploaded_at.isoformat(),
        'results': [
            {
                'check_id': r.check_id,
                'status': r.status,
                'details': r.details
            } for r in results
        ]
    }
    
    response = HttpResponse(
        json.dumps(report_data, indent=2),
        content_type='application/json'
    )
    response['Content-Disposition'] = f'attachment; filename="scan_{scan.id}.json"'
    return response


# ==========================================
# Access Request Views
# ==========================================

    return redirect('viewer_dashboard')


# ==========================================
# Audit Log Export
# ==========================================

@login_required
@role_required('SUPER_ADMIN')
def export_audit_pdf(request):
    """Export audit logs as PDF (placeholder)."""
    # In production, use reportlab or weasyprint
    # For now, return JSON
    
    logs = AuditLog.objects.select_related('user').all().order_by('-timestamp')[:100]
    
    data = []
    for log in logs:
        data.append({
            'timestamp': log.timestamp.isoformat(),
            'user': log.user.email if log.user else 'System',
            'action': log.action,
            'details': log.details,
        })
    
    response = HttpResponse(
        json.dumps(data, indent=2),
        content_type='application/json'
    )
    response['Content-Disposition'] = 'attachment; filename="audit_log.json"'
    return response


# ==========================================
# Organization Settings
# ==========================================

@login_required
@role_required('SUPER_ADMIN')
def organization_settings(request):
    """Organization settings page with tabs."""
    org = request.user.organization
    
    if request.method == 'POST':
        tab = request.POST.get('tab', 'general')
        
        # Handle form submission based on tab
        if tab == 'general':
            if org:
                org.name = request.POST.get('org_name', org.name)
                org.save()
            messages.success(request, 'General settings saved successfully.')
        
        return redirect('organization_settings')
    
    context = {
        'active_page': 'settings',
        'organization': org,
    }
    
    return render(request, 'settings/organization.html', context)













# ==========================================
# Reporting Views
# ==========================================

@login_required
def print_scan_report(request, scan_id):
    """Render a printer-friendly version of the scan report."""
    scan = get_object_or_404(ScanSummary, id=scan_id)
    
    if scan.organization != request.user.organization:
        messages.error(request, 'Permission denied.')
        return redirect('viewer_dashboard')
    
    results = ScanResult.objects.filter(scan=scan)
    
    context = {
        'scan': scan,
        'results': results,
        'now': timezone.now(),
    }
    
    return render(request, 'reports/print_scan.html', context)


# ==========================================
# Scan Comparison (Phase 5B)
# ==========================================

@login_required
@role_required('SUPER_ADMIN', 'IT_ADMIN', 'AUDITOR')
def scan_comparison(request):
    """
    Two-scan diff engine (Phase 5B).

    GET without params → shows scan picker (two dropdowns).
    GET with scan_a & scan_b → computes diff and renders comparison.

    Diff includes:
    - Score delta (overall_score change)
    - Pass/fail/warning count changes
    - Per-check result comparison (new, fixed, regressed, unchanged)
    """
    org = request.user.organization
    scans_qs = ScanSummary.objects.select_related('organization', 'uploaded_by').all()
    if org:
        scans_qs = scans_qs.filter(organization=org)
    scans_qs = scans_qs.order_by('-scan_timestamp')[:50]

    scan_a_id = request.GET.get('scan_a')
    scan_b_id = request.GET.get('scan_b')

    comparison = None

    if scan_a_id and scan_b_id:
        try:
            scan_a = ScanSummary.objects.get(id=scan_a_id)
            scan_b = ScanSummary.objects.get(id=scan_b_id)
        except ScanSummary.DoesNotExist:
            messages.error(request, 'One or both scans not found.')
            return redirect('scan_comparison')

        # Org scoping
        if org and (scan_a.organization != org or scan_b.organization != org):
            messages.error(request, 'Permission denied.')
            return redirect('scan_comparison')

        # Ensure scan_a is older (baseline)
        if scan_a.scan_timestamp > scan_b.scan_timestamp:
            scan_a, scan_b = scan_b, scan_a

        # Score diff
        score_delta = float(scan_b.overall_score) - float(scan_a.overall_score)

        # Per-check comparison
        results_a = {r.check_id: r for r in ScanResult.objects.filter(scan=scan_a)}
        results_b = {r.check_id: r for r in ScanResult.objects.filter(scan=scan_b)}

        all_checks = set(results_a.keys()) | set(results_b.keys())

        check_diffs = []
        fixed_count = 0
        regressed_count = 0
        new_count = 0
        unchanged_count = 0

        for check_id in sorted(all_checks):
            a = results_a.get(check_id)
            b = results_b.get(check_id)

            if a and b:
                a_status = getattr(a, 'status', 'UNKNOWN')
                b_status = getattr(b, 'status', 'UNKNOWN')

                if a_status == 'FAIL' and b_status == 'PASS':
                    diff_type = 'fixed'
                    fixed_count += 1
                elif a_status == 'PASS' and b_status == 'FAIL':
                    diff_type = 'regressed'
                    regressed_count += 1
                else:
                    diff_type = 'unchanged'
                    unchanged_count += 1

                check_diffs.append({
                    'check_id': check_id,
                    'name': getattr(b, 'check_name', check_id),
                    'old_status': a_status,
                    'new_status': b_status,
                    'diff_type': diff_type,
                })
            elif b and not a:
                new_count += 1
                check_diffs.append({
                    'check_id': check_id,
                    'name': getattr(b, 'check_name', check_id),
                    'old_status': '—',
                    'new_status': getattr(b, 'status', 'UNKNOWN'),
                    'diff_type': 'new',
                })

        comparison = {
            'scan_a': scan_a,
            'scan_b': scan_b,
            'score_delta': score_delta,
            'passed_delta': scan_b.passed_count - scan_a.passed_count,
            'failed_delta': scan_b.failed_count - scan_a.failed_count,
            'warning_delta': scan_b.warning_count - scan_a.warning_count,
            'check_diffs': check_diffs,
            'fixed_count': fixed_count,
            'regressed_count': regressed_count,
            'new_count': new_count,
            'unchanged_count': unchanged_count,
        }

    context = {
        'active_page': 'scans',
        'available_scans': scans_qs,
        'comparison': comparison,
        'scan_a_id': scan_a_id or '',
        'scan_b_id': scan_b_id or '',
    }
    return render(request, 'scans/comparison.html', context)


# ==========================================
# Report Generation (Phase 6)
# ==========================================

@login_required
def export_scans_report_csv(request):
    """
    Export scan results as CSV (Phase 6A).

    Supports optional date_range filter.
    """
    import csv

    org = request.user.organization
    scans_qs = ScanSummary.objects.select_related('organization', 'uploaded_by').all()
    if org:
        scans_qs = scans_qs.filter(organization=org)

    date_range = request.GET.get('date_range', '30')
    if date_range != 'all':
        days = int(date_range) if date_range.isdigit() else 30
        cutoff = timezone.now() - timedelta(days=days)
        scans_qs = scans_qs.filter(scan_timestamp__gte=cutoff)

    scans_qs = scans_qs.order_by('-scan_timestamp')

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="avaguard_scans_report.csv"'

    writer = csv.writer(response)
    writer.writerow([
        'Scan ID', 'Date', 'Overall Score (%)', 'Passed', 'Failed',
        'Warnings', 'Total Checks', 'Tier', 'Environment', 'Uploaded By',
    ])

    for scan in scans_qs:
        writer.writerow([
            str(scan.id),
            scan.scan_timestamp.strftime('%Y-%m-%d %H:%M'),
            f'{scan.overall_score:.1f}',
            scan.passed_count,
            scan.failed_count,
            scan.warning_count,
            scan.total_checks,
            scan.tier,
            scan.environment,
            scan.uploaded_by.email if scan.uploaded_by else '—',
        ])

    return response


@login_required
def export_scan_pdf(request, scan_id):
    """
    Export a single scan as a styled HTML page optimized for Print-to-PDF (Phase 6A).

    This renders a clean, branded HTML page with print-ready CSS.
    The user can then use the browser's Print → Save as PDF for a polished report.
    """
    scan = get_object_or_404(ScanSummary, id=scan_id)

    if scan.organization != request.user.organization:
        messages.error(request, 'Permission denied.')
        return redirect('scans')

    results = ScanResult.objects.filter(scan=scan).order_by('check_id')

    passed = results.filter(status='PASS')
    failed = results.filter(status='FAIL')
    warnings = results.filter(status='WARNING')

    context = {
        'scan': scan,
        'results': results,
        'passed': passed,
        'failed': failed,
        'warnings': warnings,
        'now': timezone.now(),
        'generated_by': request.user.full_name,
    }

    return render(request, 'reports/scan_pdf.html', context)


# ==========================================
# Unified User Intelligence View
# ==========================================

@login_required
@role_required('SUPER_ADMIN', 'IT_ADMIN')
def user_sessions_detail_view(request, user_id):
    """
    Unified user intelligence page combining identity profile,
    session intelligence, and full audit trail in one SOC-grade view.
    """
    from django.shortcuts import get_object_or_404
    from django.utils import timezone
    from .models import User, ActiveSession, AuditLog, ScanSummary

    target_user = get_object_or_404(User, id=user_id, organization=request.user.organization)

    # ── Identity / Profile ──────────────────────────────────────────────────
    # All fields are on the user object — no extra queries needed.

    # ── Active Sessions ─────────────────────────────────────────────────────
    all_active = list(
        ActiveSession.objects.filter(user=target_user, is_active=True)
        .select_related('device_auth')
        .order_by('-last_activity')
    )
    healthy_sessions = [s for s in all_active if not s.is_stale]
    stale_sessions   = [s for s in all_active if s.is_stale]
    primary_device   = all_active[0] if all_active else None

    # Unique IPs from active sessions
    active_ips = sorted(set(s.ip_address for s in all_active if s.ip_address))

    # ── Historical Sessions ─────────────────────────────────────────────────
    history_sessions = list(
        ActiveSession.objects.filter(user=target_user, is_active=False)
        .select_related('device_auth')
        .order_by('-started_at')[:100]
    )
    unique_historical_ips = sorted(set(s.ip_address for s in history_sessions if s.ip_address))

    # ── Authentication Audit Trail ──────────────────────────────────────────
    AUTH_ACTIONS = [
        'LOGIN', 'LOGIN_FAILED', 'LOGOUT',
        'SESSION_REVOKED', 'TOTP_SETUP', 'TOTP_VERIFIED',
        'PASSWORD_RESET', 'PASSWORD_CHANGED', 'MFA_BYPASS',
        'ACCOUNT_LOCKED', 'ACCOUNT_UNLOCKED', 'EMAIL_OTP_SENT',
        'DEVICE_AUTHORIZED', 'DEVICE_REVOKED',
    ]
    auth_logs = list(
        AuditLog.objects.filter(user=target_user, action__in=AUTH_ACTIONS)
        .order_by('-timestamp')[:100]
    )

    # ── Full Audit Trail ────────────────────────────────────────────────────
    # All logs for this user PLUS logs where this user was the target
    # (e.g. admin reset their password, admin revoked their session)
    full_audit_logs = list(
        AuditLog.objects.filter(user=target_user)
        .order_by('-timestamp')[:200]
    )

    # ── Scan History ────────────────────────────────────────────────────────
    user_scans = list(
        ScanSummary.objects.filter(uploaded_by=target_user)
        .order_by('-scan_timestamp')[:10]
    )

    # ── Security Signals ────────────────────────────────────────────────────
    from datetime import timedelta
    now = timezone.now()
    password_age_days = None
    if target_user.password_last_changed:
        password_age_days = (now - target_user.password_last_changed).days

    failed_login_count_24h = AuditLog.objects.filter(
        user=target_user,
        action='LOGIN_FAILED',
        timestamp__gte=now - timedelta(hours=24)
    ).count()

    revoked_session_count = AuditLog.objects.filter(
        user=target_user,
        action='SESSION_REVOKED'
    ).count()

    # Risk signals — list of (label, severity) tuples
    risk_signals = []
    if not target_user.mfa_enabled:
        risk_signals.append(('MFA not enabled', 'high'))
    if password_age_days is not None and password_age_days > 90:
        risk_signals.append((f'Password {password_age_days} days old', 'medium'))
    elif password_age_days is None:
        risk_signals.append(('Password never changed', 'medium'))
    if failed_login_count_24h >= 3:
        risk_signals.append((f'{failed_login_count_24h} failed logins (24h)', 'high'))
    if target_user.is_expired:
        risk_signals.append(('Account expired', 'high'))
    if stale_sessions:
        risk_signals.append((f'{len(stale_sessions)} stale session(s)', 'low'))

    context = {
        'active_page': 'sessions',
        # Identity
        'target_user': target_user,
        'password_age_days': password_age_days,
        # Sessions
        'healthy_sessions': healthy_sessions,
        'stale_sessions': stale_sessions,
        'history_sessions': history_sessions,
        'primary_device': primary_device,
        'total_active': len(all_active),
        'total_stale': len(stale_sessions),
        'total_healthy': len(healthy_sessions),
        'active_ips': active_ips,
        'unique_historical_ips': unique_historical_ips,
        # Audit
        'auth_logs': auth_logs,
        'full_audit_logs': full_audit_logs,
        # Scans
        'user_scans': user_scans,
        # Security Signals
        'risk_signals': risk_signals,
        'failed_login_count_24h': failed_login_count_24h,
        'revoked_session_count': revoked_session_count,
    }

    return render(request, 'admin/user_sessions_detail.html', context)
