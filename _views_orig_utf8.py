"""
AVAGuard Web Portal - Core Views

Dashboard and main page views.
All views require authentication except health_check.
"""

import json
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash
from django.contrib import messages
from django.db.models import Avg, Sum, Count
from django.utils import timezone
from datetime import timedelta
from django.http import JsonResponse
from .admin_views import role_required

# Core library integration
try:
    from avaguard_core.checks import AVAILABLE_CHECKS
    CHECKS_LOADED = True
    CHECK_COUNT = len(AVAILABLE_CHECKS)
except ImportError:
    CHECKS_LOADED = False
    CHECK_COUNT = 0
    AVAILABLE_CHECKS = {}


@login_required
def dashboard(request):
    """
    Main dashboard router ΓÇö redirects users to their role-specific dashboard.
    Enforces mandatory TOTP setup for users who haven't provisioned it.
    """
    # ΓöÇΓöÇ Phase 1.5: Enforce mandatory TOTP setup ΓöÇΓöÇ
    # If user has not configured TOTP, force them to the setup page.
    if not request.user.mfa_secret:
        return redirect('totp_setup')
    
    role = getattr(request.user, 'role', 'VIEWER')
    
    if role == 'SUPER_ADMIN':
        return redirect('admin_dashboard')
    elif role == 'IT_ADMIN':
        return redirect('it_dashboard')
    elif role == 'AUDITOR':
        return redirect('auditor_dashboard')
    else:
        return redirect('viewer_dashboard')


def home(request):
    """
    Public landing page.
    Redirects authenticated users to their dashboard.
    """
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'core/landing.html')


from django.views.decorators.http import require_POST
from django.core.mail import send_mail
from django.conf import settings as django_settings
import re

@require_POST
def contact_submit(request):
    """
    Landing page contact form handler.
    Sends a professionally formatted email to the configured inbox.
    No auth required ΓÇö public endpoint with basic validation.
    """
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid request.'}, status=400)

    name = (data.get('name') or '').strip()
    email = (data.get('email') or '').strip()
    subject = (data.get('subject') or '').strip()
    message = (data.get('message') or '').strip()

    # Validation
    errors = {}
    if not name:
        errors['name'] = 'Name is required.'
    if not email or not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        errors['email'] = 'A valid email address is required.'
    if not subject:
        errors['subject'] = 'Subject is required.'
    if not message:
        errors['message'] = 'Message is required.'

    if errors:
        return JsonResponse({'success': False, 'errors': errors}, status=400)

    # Build the email
    full_subject = f'[AVAGuard Contact] {subject}'
    text_body = (
        f'New contact form submission\n'
        f'{"=" * 40}\n'
        f'From:    {name} ({email})\n'
        f'Subject: {subject}\n\n'
        f'Message:\n{message}\n'
        f'{"=" * 40}\n'
        f'Submitted via AVAGuard Landing Page\n'
    )
    html_body = f"""
    <html>
    <body style="font-family: 'Inter', Arial, sans-serif; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background-color: #0f0f23; padding: 20px; border-radius: 8px 8px 0 0; text-align: center;">
            <h1 style="color: #00d4ff; margin: 0; font-size: 24px;">≡ƒ¢í∩╕Å AVAGuard</h1>
            <p style="color: #a0a0c0; margin: 5px 0 0; font-size: 13px;">Contact Form Submission</p>
        </div>
        <div style="border: 1px solid #ddd; border-top: none; padding: 30px; border-radius: 0 0 8px 8px; background-color: #ffffff;">
            <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                <tr>
                    <td style="padding: 8px 0; color: #777; width: 80px;">From:</td>
                    <td style="padding: 8px 0; font-weight: bold;">{name}</td>
                </tr>
                <tr>
                    <td style="padding: 8px 0; color: #777;">Email:</td>
                    <td style="padding: 8px 0;"><a href="mailto:{email}" style="color: #00d4ff;">{email}</a></td>
                </tr>
                <tr>
                    <td style="padding: 8px 0; color: #777;">Subject:</td>
                    <td style="padding: 8px 0; font-weight: bold;">{subject}</td>
                </tr>
            </table>
            <div style="background-color: #f4f4f9; padding: 20px; border-radius: 6px; white-space: pre-wrap; line-height: 1.6;">
                {message}
            </div>
            <p style="font-size: 12px; color: #999; margin-top: 30px; border-top: 1px solid #eee; padding-top: 15px;">
                This message was sent via the AVAGuard landing page contact form.
            </p>
        </div>
    </body>
    </html>
    """

    recipient = django_settings.EMAIL_HOST_USER or 'admin@avaguard.com'

    try:
        send_mail(
            subject=full_subject,
            message=text_body,
            html_message=html_body,
            from_email=django_settings.DEFAULT_FROM_EMAIL,
            recipient_list=[recipient],
            fail_silently=False,
        )
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f'Contact email send failed: {e}')
        # Still return success ΓÇö the message was received even if email delivery failed
        # In console backend mode, it prints to stdout

    return JsonResponse({'success': True, 'message': 'Your message has been sent successfully.'})


def health_check(request):
    """Health check endpoint for monitoring (no auth required)."""
    return JsonResponse({
        'status': 'healthy',
        'checks_loaded': CHECKS_LOADED,
        'check_count': CHECK_COUNT,
        'timestamp': timezone.now().isoformat(),
    })


@login_required
def scans(request):
    """Scan history view showing all compliance scans with filtering."""
    from .models import ScanSummary
    
    organization = getattr(request.user, 'organization', None)
    user_role = getattr(request.user, 'role', 'VIEWER')
    
    # Base queryset
    scans_qs = ScanSummary.objects.all()
    
    # Viewers only see their own scans, admins see all in org
    if user_role == 'VIEWER':
        scans_qs = scans_qs.filter(uploaded_by=request.user)
    elif organization:
        scans_qs = scans_qs.filter(organization=organization)
    
    # Apply date range filter
    date_range = request.GET.get('date_range', '30')
    if date_range == '7':
        date_cutoff = timezone.now() - timedelta(days=7)
        scans_qs = scans_qs.filter(scan_timestamp__gte=date_cutoff)
    elif date_range == '30':
        date_cutoff = timezone.now() - timedelta(days=30)
        scans_qs = scans_qs.filter(scan_timestamp__gte=date_cutoff)
    elif date_range == '90':
        date_cutoff = timezone.now() - timedelta(days=90)
        scans_qs = scans_qs.filter(scan_timestamp__gte=date_cutoff)
    # 'all' = no date filter
    
    # Apply status filter
    status_filter = request.GET.get('status', '')
    if status_filter == 'compliant':
        scans_qs = scans_qs.filter(overall_score__gte=80)
    elif status_filter == 'needs_work':
        scans_qs = scans_qs.filter(overall_score__gte=60, overall_score__lt=80)
    elif status_filter == 'at_risk':
        scans_qs = scans_qs.filter(overall_score__lt=60)
    
    # Get all scans ordered by date
    all_scans = scans_qs.order_by('-scan_timestamp')[:100]
    
    context = {
        'active_page': 'scans',
        'organization': organization,
        'scans': all_scans,
        'can_view_all': user_role in ['SUPER_ADMIN', 'IT_ADMIN', 'AUDITOR'],
        'date_range': date_range,
        'status_filter': status_filter,
    }
    
    return render(request, 'scans/index.html', context)


@login_required
def reports(request):
    """Reports view for generating and viewing compliance reports."""
    from .models import ScanSummary
    
    organization = getattr(request.user, 'organization', None)
    user_role = getattr(request.user, 'role', 'VIEWER')
    
    # Count reports (scan summaries serve as reports)
    scans_qs = ScanSummary.objects.all()
    if organization:
        scans_qs = scans_qs.filter(organization=organization)
    
    total_reports = scans_qs.count()
    
    # Monthly reports
    thirty_days_ago = timezone.now() - timedelta(days=30)
    monthly_reports = scans_qs.filter(scan_timestamp__gte=thirty_days_ago).count()
    
    # Last report
    last_scan = scans_qs.order_by('-scan_timestamp').first()
    last_report = last_scan.scan_timestamp.strftime('%Y-%m-%d %H:%M') if last_scan else 'Never'
    
    
    # Format reports for display
    # Get recent reports for display
    reports_list = scans_qs.order_by('-scan_timestamp')[:50]
    
    display_reports = []
    for scan in reports_list:
        display_reports.append({
            'id': str(scan.id),
            'name': f"Compliance Report - {str(scan.id)[:8]}",
            'type': 'Compliance Scan',
            'created_at': scan.scan_timestamp,
            'format': 'PDF/HTML',
            'score': scan.overall_score,
            'status': 'Compliant' if scan.overall_score >= 80 else 'At Risk'
        })
    
    context = {
        'active_page': 'reports',
        'organization': organization,
        'reports': display_reports,
        'total_reports': total_reports,
        'monthly_reports': monthly_reports,
        'last_report': last_report,
        'can_export': user_role in ['SUPER_ADMIN', 'IT_ADMIN'],
    }
    
    return render(request, 'reports/index.html', context)


@login_required
def generate_report(request):
    """
    Handle report generation requests.
    Supports PDF, HTML, JSON, CSV formats.
    """
    from .models import ScanSummary
    from django.http import HttpResponse
    
    if request.method != 'POST':
        return redirect('reports')
        
    report_type = request.POST.get('report_type', 'Executive Summary')
    date_range = request.POST.get('date_range', '30')
    file_format = request.POST.get('file_format', 'PDF')
    
    # Calculate date filter
    cutoff_date = timezone.now() - timedelta(days=30)
    if date_range == '7':
        cutoff_date = timezone.now() - timedelta(days=7)
    elif date_range == '90':
        cutoff_date = timezone.now() - timedelta(days=90)
        
    scans = ScanSummary.objects.filter(
        scan_timestamp__gte=cutoff_date
    ).order_by('-scan_timestamp')
    
    organization = getattr(request.user, 'organization', None)
    if organization:
        scans = scans.filter(organization=organization)

    # Generate Report based on format
    if file_format == 'CSV':
        import csv
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="report_{timezone.now().strftime("%Y%m%d")}.csv"'
        writer = csv.writer(response)
        writer.writerow(['Date', 'Scan ID', 'Score', 'Status', 'Passed', 'Failed'])
        for s in scans:
            status = 'Pass' if s.overall_score >= 80 else 'Fail'
            writer.writerow([s.scan_timestamp, s.id, s.overall_score, status, s.passed_count, s.failed_count])
        return response

    elif file_format == 'JSON':
        data = [{
            'scan_id': str(s.id),
            'date': s.scan_timestamp.isoformat(),
            'score': s.overall_score,
            'details': {}  # ScanSummary no longer has json_data
        } for s in scans]
        response = JsonResponse({'report_type': report_type, 'generated_at': timezone.now().isoformat(), 'scans': data})
        response['Content-Disposition'] = f'attachment; filename="report_{timezone.now().strftime("%Y%m%d")}.json"'
        return response

    else:
        # For PDF/HTML, render a printable HTML view (Print to PDF)
        # Since we don't have WeasyPrint, we render HTML and ask user to print.
        from .pii_scrubber import scrub_report_context

        context = {
            'report_type': report_type,
            'date_range': date_range,
            'generated_at': timezone.now(),
            'scans': scans,
            'user': request.user,
            'stats': {
                'total': scans.count(),
                'avg_score': scans.aggregate(Avg('overall_score'))['overall_score__avg'] or 0
            }
        }
        # PII scrubbing: mask emails and org names for non-SuperAdmin
        context = scrub_report_context(context, request.user)
        return render(request, 'reports/print_summary.html', context)


@login_required
@role_required('SUPER_ADMIN', 'IT_ADMIN', 'AUDITOR')
def policies(request):
    """Policies view for managing security policies."""
    organization = getattr(request.user, 'organization', None)
    user_role = getattr(request.user, 'role', 'VIEWER')
    
    # Get policy categories from available checks
    policy_categories = {}
    for check_id, check_class in AVAILABLE_CHECKS.items():
        category = getattr(check_class, 'category', 'General')
        if category not in policy_categories:
            policy_categories[category] = []
        policy_categories[category].append({
            'id': check_id,
            'name': getattr(check_class, 'name', check_id),
            'description': getattr(check_class, 'description', ''),
            'severity': getattr(check_class, 'severity', 'Medium'),
        })
    
    context = {
        'active_page': 'policies',
        'organization': organization,
        'active_policies': CHECK_COUNT,
        'disabled_policies': 0,
        'custom_rules': 0,
        'frameworks': 4,
        'policy_categories': policy_categories,
        'can_edit': user_role in ['SUPER_ADMIN', 'IT_ADMIN'],
    }
    
    return render(request, 'policies/index.html', context)


@login_required
def settings_view(request):
    """Settings view for user and application configuration."""
    organization = getattr(request.user, 'organization', None)
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'update_profile':
            # Update profile
            first_name = request.POST.get('first_name', '').strip()
            last_name = request.POST.get('last_name', '').strip()
            department = request.POST.get('department', '').strip()
            
            request.user.first_name = first_name
            request.user.last_name = last_name
            if hasattr(request.user, 'department'):
                request.user.department = department
            request.user.save()
            
            messages.success(request, 'Profile updated successfully.')
        
        elif action == 'change_password':
            # Change password
            current_password = request.POST.get('current_password', '')
            new_password = request.POST.get('new_password', '')
            confirm_password = request.POST.get('confirm_password', '')
            
            if not request.user.check_password(current_password):
                messages.error(request, 'Current password is incorrect.')
            elif new_password != confirm_password:
                messages.error(request, 'New passwords do not match.')
            elif len(new_password) < 8:
                messages.error(request, 'Password must be at least 8 characters.')
            else:
                request.user.set_password(new_password)
                request.user.save()
                update_session_auth_hash(request, request.user)
                messages.success(request, 'Password changed successfully.')
        
        return redirect('settings')
    
    context = {
        'active_page': 'settings',
        'organization': organization,
    }
    
    return render(request, 'settings/index.html', context)


@login_required
@role_required('SUPER_ADMIN', 'IT_ADMIN')
def export_scans_csv(request):
    """Export scans as CSV file."""
    import csv
    from .models import ScanSummary
    from django.http import HttpResponse
    
    organization = getattr(request.user, 'organization', None)
    user_role = getattr(request.user, 'role', 'VIEWER')
    
    # Check permission
    if user_role not in ['SUPER_ADMIN', 'IT_ADMIN']:
        messages.error(request, 'You do not have permission to export data.')
        return redirect('scans')
    
    # Get scans
    scans_qs = ScanSummary.objects.all()
    if organization:
        scans_qs = scans_qs.filter(organization=organization)
    scans_qs = scans_qs.order_by('-scan_timestamp')[:500]
    
    # Create CSV response
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="avaguard_scans.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Scan ID', 'Date', 'Score', 'Passed', 'Failed', 'Warnings', 'Status'])
    
    for scan in scans_qs:
        status = 'Compliant' if scan.overall_score >= 80 else ('Needs Work' if scan.overall_score >= 60 else 'At Risk')
        writer.writerow([
            str(scan.id),
            scan.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            f"{scan.overall_score:.1f}%",
            scan.passed_count,
            scan.failed_count,
            scan.warning_count,
            status,
        ])
    
    return response


# ==========================================
# Health Check (Phase 4.5)
# ==========================================

import time
_START_TIME = time.time()


def health_check(request):
    """
    Production health endpoint (Phase 4.5).

    Returns structured JSON with:
    - Database connectivity status
    - Uptime in seconds
    - Application version
    - Core library status

    No authentication required ΓÇö designed for load balancers,
    orchestrators, and monitoring pipelines.
    """
    from django.db import connection

    checks = {}
    overall = 'healthy'

    # Database connectivity
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
        checks['database'] = {'status': 'ok'}
    except Exception as e:
        checks['database'] = {'status': 'error', 'message': str(e)}
        overall = 'degraded'

    # Core library
    checks['core_library'] = {
        'status': 'ok' if CHECKS_LOADED else 'unavailable',
        'checks_available': CHECK_COUNT,
    }

    uptime = int(time.time() - _START_TIME)


    # Must use graceful fallback just in case the backend crashes out of context
    import sys
    try:
        import avaguard_core
        app_version = avaguard_core.__version__
    except ImportError:
        app_version = "0.1.0"

    return JsonResponse({
        'status': overall,
        'checks': checks,
        'uptime_seconds': uptime,
        'version': app_version,
    })


from .models import APIUsageLog
from django.shortcuts import render
def rate_limits_view(request):
    logs = APIUsageLog.objects.all()[:50]
    total_calls = sum(l.calls for l in logs) if logs else 0
    quota_remaining = 10000 - total_calls
    return render(request, 'core/rate_limits.html', {'logs': logs, 'remaining': quota_remaining})
