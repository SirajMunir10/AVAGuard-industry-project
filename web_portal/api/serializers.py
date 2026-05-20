"""
AVAGuard API Serializers

Defines how data is converted between Python objects and JSON for the REST API.
"""

from rest_framework import serializers
from core.models import Organization, User, ScanSummary, AuditLog


class OrganizationSerializer(serializers.ModelSerializer):
    """Serializer for Organization model."""
    class Meta:
        model = Organization
        fields = ['id', 'name', 'domain_filter', 'is_active', 'created_at']
        read_only_fields = ['id', 'created_at']


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model (read-only, excludes password)."""
    organization_name = serializers.CharField(source='organization.name', read_only=True)
    
    class Meta:
        model = User
        fields = ['id', 'email', 'organization', 'organization_name', 'role', 'is_active', 'created_at']
        read_only_fields = ['id', 'created_at']


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration."""
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ['email', 'password', 'password_confirm', 'organization']
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({"password_confirm": "Passwords do not match."})
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')
        from django.contrib.auth.hashers import make_password
        validated_data['password_hash'] = make_password(validated_data.pop('password'))
        return User.objects.create(**validated_data)


class LoginSerializer(serializers.Serializer):
    """Serializer for login request."""
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class ScanSummarySerializer(serializers.ModelSerializer):
    """Serializer for ScanSummary model."""
    organization_name = serializers.CharField(source='organization.name', read_only=True)
    user_email = serializers.CharField(source='uploaded_by.email', read_only=True)
    
    class Meta:
        model = ScanSummary
        fields = [
            'id', 'organization', 'organization_name', 'uploaded_by', 'user_email',
            'overall_score', 'passed_count', 'failed_count', 'total_checks', 'scan_timestamp'
        ]
        read_only_fields = ['scan_timestamp']


class ScanUploadSerializer(serializers.Serializer):
    """
    Serializer for receiving scan results from desktop application.
    
    Expected format from desktop:
    {
        "scan_id": "uuid",
        "overall_score": 85.5,
        "passed_count": 8,
        "failed_count": 2,
        "total_checks": 10,
        "results": [
            {
                "check_id": "1.1",
                "title": "MFA Check",
                "status": "PASS",
                "severity": "HIGH",
                ...
            }
        ]
    }
    """
    scan_id = serializers.UUIDField()
    overall_score = serializers.DecimalField(max_digits=5, decimal_places=2)
    passed_count = serializers.IntegerField()
    failed_count = serializers.IntegerField()
    total_checks = serializers.IntegerField()
    results = serializers.ListField(child=serializers.DictField(), required=False)


class AuditLogSerializer(serializers.ModelSerializer):
    """Serializer for AuditLog model."""
    user_email = serializers.CharField(source='user.email', read_only=True)
    
    class Meta:
        model = AuditLog
        fields = ['id', 'user', 'user_email', 'action', 'details', 'timestamp']
        read_only_fields = ['id', 'timestamp']


class DashboardStatsSerializer(serializers.Serializer):
    """Serializer for dashboard statistics response."""
    total_scans = serializers.IntegerField()
    average_score = serializers.DecimalField(max_digits=5, decimal_places=2)
    total_passed = serializers.IntegerField()
    total_failed = serializers.IntegerField()
    latest_scan = ScanSummarySerializer(allow_null=True)
    score_trend = serializers.ListField(child=serializers.DictField())

from core.models import Policy

class PolicySerializer(serializers.ModelSerializer):
    """Serializer for Policy model to be consumed by the desktop agent."""
    class Meta:
        model = Policy
        fields = [
            'id', 'name', 'category', 'severity', 'framework',
            'control_id', 'status', 'check_id'
        ]

