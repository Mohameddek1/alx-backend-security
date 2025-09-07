from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth import authenticate, login
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited
from django.utils.decorators import method_decorator
from django.views import View
import json

# Rate-limited login view
@csrf_exempt
@require_http_methods(["POST"])
@ratelimit(key='ip', rate='10/m', method='POST', block=True)  # Anonymous users: 5/min
@ratelimit(key='user_or_ip', rate='10/m', method='POST', block=True)  # Authenticated: 10/min
def rate_limited_login(request):
    """
    Login view with rate limiting applied.
    - Anonymous users: 5 requests per minute
    - Authenticated users: 10 requests per minute
    """
    try:
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return JsonResponse({
                'error': 'Username and password are required'
            }, status=400)
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return JsonResponse({
                'success': True,
                'message': f'Welcome, {user.username}!',
                'user_id': user.id
            })
        else:
            return JsonResponse({
                'error': 'Invalid credentials'
            }, status=401)
            
    except json.JSONDecodeError:
        return JsonResponse({
            'error': 'Invalid JSON data'
        }, status=400)
    except Ratelimited:
        return JsonResponse({
            'error': 'Rate limit exceeded. Please try again later.'
        }, status=429)

# Sensitive API endpoint with rate limiting
@ratelimit(key='ip', rate='5/m', method='GET', block=True)  # 5 requests per minute
def sensitive_api_view(request):
    """
    A sensitive API endpoint that requires rate limiting.
    """
    try:
        # Simulate sensitive data access
        sensitive_data = {
            'user_count': 1500,
            'system_status': 'operational',
            'last_backup': '2025-09-07T10:30:00Z',
            'message': 'This is sensitive system information'
        }
        
        return JsonResponse({
            'success': True,
            'data': sensitive_data
        })
        
    except Ratelimited:
        return JsonResponse({
            'error': 'Rate limit exceeded for sensitive endpoint'
        }, status=429)

# Password reset with rate limiting
@csrf_exempt
@require_http_methods(["POST"])
@ratelimit(key='ip', rate='3/m', method='POST', block=True)  # Very restrictive: 3/min
def password_reset_request(request):
    """
    Password reset endpoint with strict rate limiting.
    """
    try:
        data = json.loads(request.body)
        email = data.get('email')
        
        if not email:
            return JsonResponse({
                'error': 'Email is required'
            }, status=400)
        
        # Simulate password reset logic
        return JsonResponse({
            'success': True,
            'message': f'Password reset email sent to {email}'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'error': 'Invalid JSON data'
        }, status=400)
    except Ratelimited:
        return JsonResponse({
            'error': 'Too many password reset attempts. Please try again later.'
        }, status=429)

# Class-based view with rate limiting
class RateLimitedAPIView(View):
    @method_decorator(ratelimit(key='ip', rate='10/m', method='GET', block=True))
    def get(self, request):
        """API endpoint with rate limiting using class-based view."""
        return JsonResponse({
            'message': 'This is a rate-limited API endpoint',
            'timestamp': '2025-09-07T15:45:00Z',
            'ip_address': request.META.get('REMOTE_ADDR', 'Unknown')
        })
    
    @method_decorator(ratelimit(key='user_or_ip', rate='5/m', method='POST', block=True))
    def post(self, request):
        """POST endpoint with different rate limit."""
        try:
            data = json.loads(request.body)
            return JsonResponse({
                'message': 'Data received successfully',
                'received_data': data
            })
        except json.JSONDecodeError:
            return JsonResponse({
                'error': 'Invalid JSON data'
            }, status=400)

# Helper view to check current rate limit status
@ratelimit(key='ip', rate='20/m', method='GET', block=False)  # Don't block, just check
def rate_limit_status(request):
    """
    Check current rate limit status for debugging.
    """
    was_limited = getattr(request, 'limited', False)
    
    return JsonResponse({
        'ip_address': request.META.get('REMOTE_ADDR', 'Unknown'),
        'was_limited': was_limited,
        'message': 'Rate limit status check',
        'is_authenticated': request.user.is_authenticated,
        'username': request.user.username if request.user.is_authenticated else 'Anonymous'
    })
