import re
from django.shortcuts import redirect
from django.urls import reverse
from django.conf import settings

class FirstLoginMiddleware:
    """
    Middleware to enforce First Login flows and Password changes.
    Intercepts authenticated requests and forces users to:
    1. Change their password if required.
    2. Set up MFA if not configured.
    """
    def __init__(self, get_response):
        self.get_response = get_response

        # Paths that are strictly whitelisted to prevent redirect loops
        self.whitelisted_paths = [
            '/auth/logout/',
            '/auth/login/',
            '/auth/mfa/verify/',
            '/auth/mfa/totp-setup/',
            '/auth/set-password/',
            '/api/', # Exclude APIs for now or handle them via 403
        ]

    def __call__(self, request):
        if not request.user.is_authenticated:
            return self.get_response(request)

        # Skip static/media files and API
        path = request.path_info
        if path.startswith(settings.STATIC_URL) or path.startswith(settings.MEDIA_URL) or path.startswith('/api/'):
            return self.get_response(request)

        user = request.user
        
        needs_password_change = getattr(user, 'is_first_login', False) or getattr(user, 'password_change_required', False)
        needs_mfa_setup = not getattr(user, 'mfa_enabled', False)

        # 1. Force Password Change (highest priority)
        if needs_password_change:
            if path not in ['/auth/logout/', '/auth/login/', '/auth/set-password/'] and not path.startswith('/auth/mfa/verify/'):
                # Note: mfa/verify is allowed if they have MFA but need to change password (though typically password change happens first)
                return redirect('set_password')

        # 2. Force MFA Setup
        elif needs_mfa_setup:
            if path not in ['/auth/logout/', '/auth/login/', '/auth/mfa/totp-setup/'] and not path.startswith('/auth/mfa/verify/'):
                return redirect('totp_setup')

        # If they don't need setup, let them access whitelisted paths or normal pages
        return self.get_response(request)

class SecurityHeadersMiddleware:
    """
    Applies security-related HTTP headers to all responses.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        return response

class RateLimitMiddleware:
    """
    Limits login attempts to 5 per minute per IP address.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path_info == '/auth/login/' and request.method == 'POST':
            from django.core.cache import cache
            from django.http import JsonResponse, HttpResponse
            
            # Get client IP
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip = x_forwarded_for.split(',')[0]
            else:
                ip = request.META.get('REMOTE_ADDR')
                
            cache_key = f'login_attempts_{ip}'
            attempts = cache.get(cache_key, 0)
            
            if attempts >= 5:
                # Proper 429 response
                if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                    return JsonResponse({'error': 'Too many attempts. Please try again later.'}, status=429)
                from django.shortcuts import render
                return render(request, 'auth/login.html', {
                    'rate_limited': True, 
                    'step': 'credentials'
                }, status=429)
                
            # Increment and set timeout to 120 seconds
            cache.set(cache_key, attempts + 1, 120)
            
        return self.get_response(request)
