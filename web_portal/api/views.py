"""
AVAGuard API Views

REST API endpoints for desktop application integration and web dashboard.
Implements the Tethered Security Model with 2FA and device authorization.
"""

import logging
import uuid
from decimal import Decimal
from django.db.models import Avg, Sum
from django.contrib.auth.hashers import check_password
from django.utils import timezone
from rest_framework import status, viewsets, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework_simplejwt.tokens import RefreshToken

from core.models import (
    Organization, User, ScanSummary, AuditLog,
    DeviceAuthorization, OTPVerification, ActiveSession
)
from core.services import OTPService, DeviceAuthService
from .serializers import (
    OrganizationSerializer,
    UserSerializer,
    UserRegistrationSerializer,
    LoginSerializer,
    ScanSummarySerializer,
    ScanUploadSerializer,
    AuditLogSerializer,
    DashboardStatsSerializer,
)

logger = logging.getLogger(__name__)

class IsActiveSession(permissions.BasePermission):
    """
    Checks if the JWT token corresponds to a revoked session.
    Returns 403 Forbidden if the session was explicitly revoked.

    Design:
    - If the session record is NOT FOUND → allow (fresh login, record may not exist yet).
    - If the session record IS FOUND but is_active=False → block (explicitly revoked).
    - If the device_auth is REVOKED → block.
    - All other cases → allow.
    """
    message = "Session has been revoked."

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
            
        # Check if auth token exists and has jti
        if hasattr(request, 'auth') and request.auth and hasattr(request.auth, 'get'):
            jti = request.auth.get('jti')
            if jti:
                try:
                    session = ActiveSession.objects.select_related('device_auth').get(jwt_jti=jti)
                    # Session exists — check if it was revoked
                    if not session.is_active:
                        return False  # Explicitly revoked
                    if session.device_auth and session.device_auth.status == 'REVOKED':
                        return False  # Device revoked
                    return True
                except ActiveSession.DoesNotExist:
                    # No session record found for this JWT.
                    # This is expected for fresh logins where the polling hasn't created
                    # the ActiveSession yet, or the OTP path was used without device_token.
                    # Allow — the JWT itself is valid (verified by SimpleJWT).
                    return True
                    
        # If no JWT is used, just pass (e.g. SessionAuth for web views)
        return True


# ==============================================================================
# Authentication Endpoints
# ==============================================================================

class LoginView(APIView):
    """
    POST /api/auth/login/
    
    Step 1 of 2FA authentication. Validates credentials and sends OTP.
    Returns a session_id for OTP verification.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        
        try:
            user = User.objects.get(email=email, is_active=True)
        except User.DoesNotExist:
            AuditLog.log(
                action='LOGIN_FAILED',
                details=f"Failed login attempt for email: {email}"
            )
            return Response(
                {"error": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Check password using Django's built-in method
        if not user.check_password(password):
            AuditLog.log(
                action='LOGIN_FAILED',
                user=user,
                details=f"Invalid password for: {email}"
            )
            return Response(
                {"error": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        # If 2FA is disabled, return tokens directly
        if getattr(user, 'mfa_enabled', False) is False:
            refresh = RefreshToken.for_user(user)
            refresh['email'] = user.email
            refresh['role'] = user.role
            if user.organization:
                refresh['organization_id'] = str(user.organization.id)
                
            AuditLog.log(
                action='LOGIN',
                user=user,
                details="API login successful (2FA disabled)"
            )
            
            return Response({
                "verified": True,
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "user": UserSerializer(user).data,
                "message": "Login successful"
            })
        
        # Generate session ID for OTP tracking
        session_id = OTPService.generate_session_id()
        
        # Generate and send OTP
        code = OTPService.generate_otp(user, session_id)
        OTPService.send_otp(user, code)
        
        return Response({
            "otp_required": True,
            "session_id": session_id,
            "message": "Verification code sent. Check server console.",
            "expires_in": OTPService.OTP_EXPIRY_SECONDS
        })


class VerifyOTPView(APIView):
    """
    POST /api/auth/verify-otp/
    
    Step 2 of 2FA authentication. Verifies OTP code.
    If device_token is provided, also approves the device.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        email = request.data.get('email')
        code = request.data.get('code')
        session_id = request.data.get('session_id')
        device_token = request.data.get('device_token')  # Optional
        
        if not all([email, code, session_id]):
            return Response(
                {"error": "email, code, and session_id are required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            user = User.objects.get(email=email, is_active=True)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Verify OTP
        success, message = OTPService.verify_otp(user, code, session_id)
        
        if not success:
            return Response(
                {"error": message, "verified": False},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        
        # Add custom claims
        refresh['email'] = user.email
        refresh['role'] = user.role
        if user.organization:
            refresh['organization_id'] = str(user.organization.id)
        
        # Get JWT ID for session tracking
        jwt_jti = str(refresh.access_token['jti'])
        
        response_data = {
            "verified": True,
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": UserSerializer(user).data,
        }
        
        # If device_token provided, approve the device
        if device_token:
            success, msg, device_auth = DeviceAuthService.approve_device(device_token, user)
            if success and device_auth:
                # Create active session
                DeviceAuthService.create_active_session(
                    user=user,
                    device_auth=device_auth,
                    jwt_jti=jwt_jti,
                    ip_address=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
                response_data['device_authorized'] = True
            else:
                response_data['device_authorized'] = False
                response_data['device_message'] = msg
        
        AuditLog.log(
            action='LOGIN',
            user=user,
            details="2FA login successful"
        )
        
        return Response(response_data)


class RegisterView(APIView):
    """
    POST /api/auth/register/
    
    Register a new user (admin approval may be required).
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        AuditLog.objects.create(
            user=user,
            action="USER_REGISTERED",
            details=f"New user registered: {user.email}"
        )
        
        return Response(
            UserSerializer(user).data,
            status=status.HTTP_201_CREATED
        )


class CurrentUserView(APIView):
    """
    GET /api/auth/me/
    
    Get current authenticated user info.
    """
    permission_classes = [permissions.IsAuthenticated, IsActiveSession]
    
    def get(self, request):
        # Assuming request.user.id is the user ID from JWT
        try:
            user = User.objects.get(id=request.user.id)
            return Response(UserSerializer(user).data)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found"},
                status=status.HTTP_404_NOT_FOUND
            )


# ==============================================================================
# Scan Endpoints
# ==============================================================================

class ScanUploadView(APIView):
    """
    POST /api/scans/upload/
    
    Receive scan results from desktop application.
    This is the primary integration point between desktop and web.
    """
    permission_classes = [permissions.IsAuthenticated, IsActiveSession]
    
    def post(self, request):
        serializer = ScanUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        data = serializer.validated_data
        
        try:
            user = User.objects.get(id=request.user.id)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Create or update scan summary
        scan, created = ScanSummary.objects.update_or_create(
            id=data['scan_id'],
            defaults={
                'organization': user.organization,
                'uploaded_by': user,
                'overall_score': data['overall_score'],
                'passed_count': data['passed_count'],
                'failed_count': data['failed_count'],
                'total_checks': data['total_checks'],
            }
        )
        
        # Store individual check results
        if 'results' in data and data['results']:
            from core.models import ScanResult
            import json
            
            # Clear existing results for this scan to avoid duplicates on retry
            ScanResult.objects.filter(scan=scan).delete()
            
            results_to_create = []
            for res in data['results']:
                # Handle fields that might be JSON strings or dicts
                evidence = res.get('evidence', {})
                if isinstance(evidence, str) and evidence:
                    try:
                        evidence = json.loads(evidence)
                    except:
                        evidence = {}
                
                resources = res.get('non_compliant_resources', [])
                if isinstance(resources, str) and resources:
                    try:
                        resources = json.loads(resources)
                    except:
                        resources = []

                results_to_create.append(ScanResult(
                    scan=scan,
                    check_id=res.get('check_id'),
                    cis_control_id=res.get('cis_control_id', ''),
                    title=res.get('title', 'Unknown Check'),
                    status=res.get('status', 'FAIL'),
                    severity=res.get('severity', 'MEDIUM'),
                    compliant_count=res.get('compliant_count', 0),
                    non_compliant_count=res.get('non_compliant_count', 0),
                    total_count=res.get('total_count', 0),
                    compliance_percentage=res.get('compliance_percentage', 0.0),
                    details=res.get('details') or '',
                    remediation=res.get('remediation') or '',
                    error_message=res.get('error_message') or '',
                    evidence=evidence,
                    non_compliant_resources=resources,
                    duration_seconds=res.get('duration_seconds', 0.0)
                ))
            
            # Bulk create for performance
            if results_to_create:
                ScanResult.objects.bulk_create(results_to_create, batch_size=100)
        
        action = "SCAN_UPLOADED" if created else "SCAN_UPDATED"
        AuditLog.objects.create(
            user=user,
            action=action,
            details=f"Scan {data['scan_id']} - Score: {data['overall_score']}%"
        )
        
        logger.info(f"Scan uploaded: {data['scan_id']} by {user.email}")
        
        return Response(
            ScanSummarySerializer(scan).data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK
        )


class ScanListView(APIView):
    """
    GET /api/scans/
    
    List all scans for the authenticated user's organization.
    """
    permission_classes = [permissions.IsAuthenticated, IsActiveSession]
    
    def get(self, request):
        try:
            user = User.objects.get(id=request.user.id)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        scans = ScanSummary.objects.filter(
            organization=user.organization
        ).order_by('-scan_timestamp')[:50]
        
        serializer = ScanSummarySerializer(scans, many=True)
        return Response(serializer.data)


class ScanDetailView(APIView):
    """
    GET /api/scans/<uuid:pk>/
    
    Get details of a specific scan.
    """
    permission_classes = [permissions.IsAuthenticated, IsActiveSession]
    
    def get(self, request, pk):
        try:
            user = User.objects.get(id=request.user.id)
            scan = ScanSummary.objects.get(
                id=pk,
                organization=user.organization
            )
        except (User.DoesNotExist, ScanSummary.DoesNotExist):
            return Response(
                {"error": "Scan not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        serializer = ScanSummarySerializer(scan)
        return Response(serializer.data)


# ==============================================================================
# Dashboard Endpoints
# ==============================================================================

class DashboardStatsView(APIView):
    """
    GET /api/dashboard/stats/
    
    Get dashboard statistics for the authenticated user's organization.
    """
    permission_classes = [permissions.IsAuthenticated, IsActiveSession]
    
    def get(self, request):
        try:
            user = User.objects.get(id=request.user.id)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        org_scans = ScanSummary.objects.filter(organization=user.organization)
        
        # Calculate statistics
        total_scans = org_scans.count()
        
        if total_scans > 0:
            avg_score = org_scans.aggregate(avg=Avg('overall_score'))['avg'] or Decimal('0')
            total_passed = org_scans.aggregate(total=Sum('passed_count'))['total'] or 0
            total_failed = org_scans.aggregate(total=Sum('failed_count'))['total'] or 0
            latest_scan = org_scans.order_by('-scan_timestamp').first()
            
            # Score trend (last 10 scans)
            recent_scans = org_scans.order_by('-scan_timestamp')[:10]
            score_trend = [
                {
                    "date": scan.scan_timestamp.strftime("%Y-%m-%d"),
                    "score": float(scan.overall_score)
                }
                for scan in reversed(list(recent_scans))
            ]
        else:
            avg_score = Decimal('0')
            total_passed = 0
            total_failed = 0
            latest_scan = None
            score_trend = []
        
        data = {
            "total_scans": total_scans,
            "average_score": avg_score,
            "total_passed": total_passed,
            "total_failed": total_failed,
            "latest_scan": ScanSummarySerializer(latest_scan).data if latest_scan else None,
            "score_trend": score_trend,
        }
        
        serializer = DashboardStatsSerializer(data)
        return Response(serializer.data)


# ==============================================================================
# Audit Log Endpoints
# ==============================================================================

class AuditLogListView(APIView):
    """
    GET /api/audit-logs/
    
    List audit logs for the authenticated user's organization.
    Admin only.
    """
    permission_classes = [permissions.IsAuthenticated, IsActiveSession]
    
    def get(self, request):
        try:
            user = User.objects.get(id=request.user.id)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        if user.role not in ['SUPER_ADMIN', 'IT_ADMIN']:
            return Response(
                {"error": "Admin access required"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        logs = AuditLog.objects.filter(
            organization=user.organization
        ).order_by('-timestamp')[:100]
        
        serializer = AuditLogSerializer(logs, many=True)
        return Response(serializer.data)


# ==============================================================================
# Device Authorization Endpoints (Tethered Security Model)
# ==============================================================================

class DeviceRegisterView(APIView):
    """
    POST /api/auth/device/register/
    
    Desktop app registers a new device token.
    Returns the token status and expiry time.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        # Generate token if not provided
        device_token = request.data.get('device_token') or DeviceAuthService.generate_device_token()
        device_name = request.data.get('device_name', '')
        
        # Check if token already exists
        existing = DeviceAuthorization.objects.filter(device_token=device_token).first()
        if existing:
            return Response({
                "device_token": device_token,
                "status": existing.status,
                "message": "Token already registered"
            })
        
        device_auth = DeviceAuthService.register_device(
            device_token=device_token,
            device_name=device_name,
            ip_address=request.META.get('REMOTE_ADDR')
        )
        
        return Response({
            "device_token": device_auth.device_token,
            "status": device_auth.status,
            "expires_at": device_auth.expires_at.isoformat(),
            "expires_in_seconds": DeviceAuthService.TOKEN_EXPIRY_MINUTES * 60,
            "authorize_url": f"/auth/authorize-device/?token={device_auth.device_token}"
        }, status=status.HTTP_201_CREATED)


class DeviceStatusView(APIView):
    """
    GET /api/auth/device/status/<token>/
    
    Desktop app polls this to check if device is authorized.
    Returns status and JWT if approved.
    """
    permission_classes = [permissions.AllowAny]
    
    def get(self, request, token):
        device_auth, status_msg = DeviceAuthService.get_device_status(token)
        
        if device_auth is None:
            return Response(
                {"error": "Token not found", "status": "NOT_FOUND"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        response_data = {
            "status": device_auth.status,
            "created_at": device_auth.created_at.isoformat(),
        }
        
        if device_auth.status == 'APPROVED' and device_auth.user:
            # Generate JWT for the authorized user
            user = device_auth.user
            refresh = RefreshToken.for_user(user)
            
            refresh['email'] = user.email
            refresh['role'] = user.role
            refresh['device_token'] = token
            if user.organization:
                refresh['organization_id'] = str(user.organization.id)
            
            jwt_jti = str(refresh.access_token['jti'])
            
            # Close any existing active sessions for this device before creating a new one.
            # This prevents stale session records from blocking new JWTs.
            ActiveSession.objects.filter(
                device_auth=device_auth,
                is_active=True
            ).update(is_active=False)

            # Always create a fresh ActiveSession for the new JWT
            DeviceAuthService.create_active_session(
                user=user,
                device_auth=device_auth,
                jwt_jti=jwt_jti,
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            response_data.update({
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "name": user.full_name,
                    "role": user.role,
                },
                "approved_at": device_auth.approved_at.isoformat() if device_auth.approved_at else None
            })
        elif device_auth.status == 'EXPIRED':
            response_data["message"] = "Token has expired. Please restart the desktop app."
        elif device_auth.status == 'REVOKED':
            response_data["message"] = "Session has been revoked by administrator."
        
        return Response(response_data)


class DeviceApproveView(APIView):
    """
    POST /api/auth/device/approve/<token>/
    
    Web user approves a device token.
    Requires authenticated user.
    """
    permission_classes = [permissions.IsAuthenticated, IsActiveSession]
    
    def post(self, request, token):
        try:
            user = User.objects.get(id=request.user.id)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        success, message, device_auth = DeviceAuthService.approve_device(token, user)
        
        if success:
            return Response({
                "success": True,
                "message": message,
                "device_token": token
            })
        else:
            return Response(
                {"success": False, "error": message},
                status=status.HTTP_400_BAD_REQUEST
            )


class HeartbeatView(APIView):
    """
    POST /api/auth/heartbeat/
    
    Desktop app sends heartbeat every 5 minutes.
    Returns 401 if session has been revoked.
    """
    permission_classes = [permissions.IsAuthenticated, IsActiveSession]
    
    def post(self, request):
        device_token = request.data.get('device_token')
        
        if not device_token:
            return Response(
                {"error": "device_token required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        is_valid, message = DeviceAuthService.update_heartbeat(device_token)
        
        if not is_valid:
            return Response(
                {"error": message, "revoked": True},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        return Response({
            "status": "ok",
            "timestamp": timezone.now().isoformat()
        })


# ==============================================================================
# Admin Session Management
# ==============================================================================

class ActiveSessionsView(APIView):
    """
    GET /api/admin/sessions/
    
    List all active desktop sessions. Admin only.
    """
    permission_classes = [permissions.IsAuthenticated, IsActiveSession]
    
    def get(self, request):
        try:
            user = User.objects.get(id=request.user.id)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        if user.role not in ['SUPER_ADMIN', 'IT_ADMIN']:
            return Response(
                {"error": "Admin access required"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Get active sessions for user's organization
        sessions = DeviceAuthService.get_active_sessions(user.organization)
        
        session_data = [{
            "id": str(s.id),
            "user_email": s.user.email,
            "user_name": s.user.full_name,
            "user_role": s.user.role,
            "started_at": s.started_at.isoformat(),
            "last_activity": s.last_activity.isoformat(),
            "device_name": s.device_auth.device_name if s.device_auth else "",
            "ip_address": s.ip_address,
        } for s in sessions]
        
        return Response({
            "count": len(session_data),
            "sessions": session_data
        })


class RevokeSessionView(APIView):
    """
    POST /api/admin/sessions/<uuid:pk>/revoke/
    
    Revoke an active session. Admin only.
    """
    permission_classes = [permissions.IsAuthenticated, IsActiveSession]
    
    def post(self, request, pk):
        try:
            user = User.objects.get(id=request.user.id)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        if user.role not in ['SUPER_ADMIN', 'IT_ADMIN']:
            return Response(
                {"error": "Admin access required"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        success, message = DeviceAuthService.revoke_session(str(pk), user)
        
        if success:
            return Response({"success": True, "message": message})
        else:
            return Response(
                {"success": False, "error": message},
                status=status.HTTP_400_BAD_REQUEST
            )


from core.models import APIUsageLog
from rest_framework.views import APIView
from rest_framework.response import Response

class APILogView(APIView):
    def post(self, request):
        calls = request.data.get('calls', 0)
        endpoint = request.data.get('endpoint', 'graph.microsoft.com')
        APIUsageLog.objects.create(endpoint=endpoint, calls=calls)
        return Response({"status": "success"})


# ==============================================================================
# Policy Sync Endpoints
# ==============================================================================
from core.models import Policy
from .serializers import PolicySerializer
from django.db.models import Q

class ActivePoliciesView(APIView):
    """
    GET /api/policies/active/
    
    Get all active policies for the authenticated user's organization.
    Includes both global policies (organization=None) and org-specific policies.
    """
    permission_classes = [permissions.IsAuthenticated, IsActiveSession]
    
    def get(self, request):
        try:
            user = User.objects.get(id=request.user.id)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found"},
                status=status.HTTP_404_NOT_FOUND
            )
            
        # Fetch ACTIVE policies that are either global (null org) or belong to the user's org
        policies = Policy.objects.filter(
            Q(organization=user.organization) | Q(organization__isnull=True),
            status='ACTIVE'
        ).order_by('category', 'severity', 'name')
        
        serializer = PolicySerializer(policies, many=True)
        return Response(serializer.data)
