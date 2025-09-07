from django.contrib import admin
from django.urls import path, include
from ip_tracking import views

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Rate-limited authentication endpoints
    path('api/login/', views.rate_limited_login, name='rate_limited_login'),
    path('api/password-reset/', views.password_reset_request, name='password_reset'),
    
    # Sensitive API endpoints
    path('api/sensitive/', views.sensitive_api_view, name='sensitive_api'),
    path('api/status/', views.rate_limit_status, name='rate_limit_status'),
    
    # Class-based view with rate limiting
    path('api/data/', views.RateLimitedAPIView.as_view(), name='rate_limited_api'),
]
