"""
AVAGuard Web Portal - Core URL Configuration
"""

from django.urls import path
from . import views
from . import auth_views
from . import admin_views
from . import user_views
from . import mfa_views
from . import notification_views

urlpatterns = [
    # Main pages
    path('', views.home, name='home'),
    path('contact/', views.contact_submit, name='contact_submit'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('scans/', views.scans, name='scans'),
    path('scans/export-csv/', views.export_scans_csv, name='export_scans_csv'),
    path('reports/', views.reports, name='reports'),
    path('reports/generate/', views.generate_report, name='generate_report'),
    path('policies/', views.policies, name='policies'),
    path('settings/', views.settings_view, name='settings'),
    path('settings/organization/', admin_views.organization_settings, name='organization_settings'),
    path('health/', views.health_check, name='health_check'),
    path('portal/rate-limits/', views.rate_limits_view, name='rate_limits'),
    
    # Authentication (Web-based)
    path('auth/login/', auth_views.login_view, name='login'),
    path('auth/logout/', auth_views.logout_view, name='logout'),
    path('auth/verify-otp/', auth_views.verify_otp_view, name='verify_otp'),
    path('auth/authorize-device/', auth_views.authorize_device_view, name='authorize_device'),
    path('auth/set-password/', auth_views.set_password_view, name='set_password'),
    path('auth/request-extension/', auth_views.request_extension_view, name='request_extension'),
    
    # Enterprise MFA (Phase 1.5)
    path('auth/mfa/verify/', mfa_views.mfa_verify_view, name='mfa_verify'),
    path('auth/mfa/totp-setup/', mfa_views.totp_setup_view, name='totp_setup'),
    path('auth/sudo/confirm/', mfa_views.sudo_confirm_view, name='sudo_confirm'),
    
    # Role-based Dashboards
    path('dashboard/role/', admin_views.role_based_dashboard, name='role_dashboard'),
    path('dashboard/admin/', admin_views.admin_dashboard, name='admin_dashboard'),
    path('dashboard/it/', admin_views.it_dashboard, name='it_dashboard'),
    path('dashboard/viewer/', admin_views.viewer_dashboard, name='viewer_dashboard'),
    path('dashboard/auditor/', admin_views.auditor_dashboard, name='auditor_dashboard'),
    
    # User Management (Super Admin)
    path('system/users/', auth_views.user_management_view, name='user_management'),
    path('system/users/add/', admin_views.add_user, name='add_user'),
    path('system/users/<uuid:user_id>/toggle-status/', admin_views.toggle_user_status, name='toggle_user_status'),
    path('system/users/<uuid:user_id>/reset-password/', admin_views.reset_user_password, name='reset_user_password'),
    
    # Session Management
    path('system/sessions/', auth_views.active_sessions_view, name='active_sessions'),
    path('system/sessions/<uuid:session_id>/revoke/', admin_views.revoke_session, name='revoke_session'),
    path('system/users/<uuid:user_id>/sessions/', admin_views.user_sessions_detail_view, name='user_sessions_detail'),
    
    # Audit Logs
    path('system/audit-logs/', admin_views.audit_logs, name='audit_logs'),
    path('system/audit/export/', admin_views.export_audit_pdf, name='export_audit_pdf'),
    
    # Notifications
    path('notifications/', notification_views.notifications_view, name='notifications'),
    path('notifications/<uuid:notification_id>/approve/', notification_views.approve_extension, name='approve_extension'),
    path('notifications/<uuid:notification_id>/deny/', notification_views.deny_extension, name='deny_extension'),
    
    # Scan Management
    path('scans/<uuid:scan_id>/', admin_views.scan_detail, name='scan_detail'),
    path('scans/<uuid:scan_id>/download/', admin_views.download_report, name='download_report'),
    path('scans/<uuid:scan_id>/print/', admin_views.print_scan_report, name='print_scan_report'),
    path('scans/<uuid:scan_id>/export-pdf/', admin_views.export_scan_pdf, name='export_scan_pdf'),
    
    # Scan Comparison (Phase 5B)
    path('scans/compare/', admin_views.scan_comparison, name='scan_comparison'),
    
    # Report Exports (Phase 6)
    path('reports/export-csv/', admin_views.export_scans_report_csv, name='export_scans_report_csv'),
    
    # ==========================================
    # User Management API (AJAX Endpoints)
    # ==========================================
    path('api/users/search/', user_views.search_users, name='api_search_users'),
    path('api/users/<uuid:user_id>/details/', user_views.get_user_details, name='api_user_details'),
    path('api/users/<uuid:user_id>/toggle-2fa/', user_views.toggle_user_2fa, name='api_toggle_2fa'),
    path('api/users/<uuid:user_id>/reset-2fa/', user_views.reset_user_2fa, name='api_reset_2fa'),
    path('api/users/<uuid:user_id>/toggle-status/', user_views.toggle_user_status, name='api_toggle_status'),
    path('api/users/<uuid:user_id>/force-reset/', user_views.force_password_reset, name='api_force_reset'),
    path('api/users/<uuid:user_id>/invalidate-sessions/', user_views.invalidate_user_sessions, name='api_invalidate_sessions'),
    path('api/users/<uuid:user_id>/set-expiry/', user_views.set_user_expiry, name='api_set_expiry'),
    path('api/users/<uuid:user_id>/update-info/', user_views.update_user_info, name='api_update_info'),
    path('api/users/bulk-action/', user_views.bulk_user_action, name='api_bulk_action'),

    # Session Heartbeat & Lifecycle (4.x)
    path('api/sessions/heartbeat/', user_views.session_heartbeat, name='api_session_heartbeat'),
    path('api/sessions/cleanup/', user_views.cleanup_stale_sessions, name='api_sessions_cleanup'),
]




