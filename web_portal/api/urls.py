"""
AVAGuard API URL Configuration
"""

from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from . import views
from core import views as core_views

app_name = 'api'

urlpatterns = [
    # Authentication (2FA)
    path('auth/login/', views.LoginView.as_view(), name='login'),
    path('auth/verify-otp/', views.VerifyOTPView.as_view(), name='verify_otp'),
    path('auth/register/', views.RegisterView.as_view(), name='register'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/me/', views.CurrentUserView.as_view(), name='current_user'),
    
    # Device Authorization (Tethered Security)
    path('auth/device/register/', views.DeviceRegisterView.as_view(), name='device_register'),
    path('auth/device/status/<str:token>/', views.DeviceStatusView.as_view(), name='device_status'),
    path('auth/device/approve/<str:token>/', views.DeviceApproveView.as_view(), name='device_approve'),
    path('auth/heartbeat/', views.HeartbeatView.as_view(), name='heartbeat'),
    
    # Scans
    path('scans/', views.ScanListView.as_view(), name='scan_list'),
    path('scans/upload/', views.ScanUploadView.as_view(), name='scan_upload'),
    path('scans/<uuid:pk>/', views.ScanDetailView.as_view(), name='scan_detail'),
    
    # Dashboard
    path('dashboard/stats/', views.DashboardStatsView.as_view(), name='dashboard_stats'),
    
    # Admin
    path('admin/sessions/', views.ActiveSessionsView.as_view(), name='active_sessions'),
    path('admin/sessions/<uuid:pk>/revoke/', views.RevokeSessionView.as_view(), name='revoke_session'),
    
    # Audit
    path('audit-logs/', views.AuditLogListView.as_view(), name='audit_logs'),
    
    # Health Check Endpoint
    path('health/', core_views.health_check, name='api_health_check'),
    path('rate-limits/log/', views.APILogView.as_view(), name='api_rate_log'),
    
    # Policies
    path('policies/active/', views.ActivePoliciesView.as_view(), name='active_policies'),
]

