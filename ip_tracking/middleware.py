from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin
from django.core.cache import cache
from .models import RequestLog, BlockedIP
import requests
import json

class IPTrackingMiddleware(MiddlewareMixin):
    def get_client_ip(self, request):
        """Get the client's IP address, accounting for proxies."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def get_geolocation(self, ip_address):
        """Get geolocation data for an IP address with caching."""
        # Check cache first (24-hour cache)
        cache_key = f"geolocation_{ip_address}"
        cached_data = cache.get(cache_key)
        if cached_data:
            return cached_data

        # Skip geolocation for local/private IPs
        if ip_address in ['127.0.0.1', 'localhost'] or ip_address.startswith('192.168.') or ip_address.startswith('10.'):
            geo_data = {'country': 'Local', 'city': 'Local'}
            cache.set(cache_key, geo_data, 86400)  # Cache for 24 hours
            return geo_data

        try:
            # Using ipinfo.io API (free tier allows 50,000 requests/month)
            response = requests.get(f'http://ipinfo.io/{ip_address}/json', timeout=5)
            if response.status_code == 200:
                data = response.json()
                geo_data = {
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown')
                }
                # Cache for 24 hours (86400 seconds)
                cache.set(cache_key, geo_data, 86400)
                return geo_data
        except requests.RequestException:
            # Handle network errors gracefully
            pass

        # Default fallback
        geo_data = {'country': 'Unknown', 'city': 'Unknown'}
        cache.set(cache_key, geo_data, 3600)  # Cache failures for 1 hour only
        return geo_data

    def process_request(self, request):
        # Get client IP address
        ip_address = self.get_client_ip(request)
        
        # Check if IP is blacklisted
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Access denied: Your IP address has been blocked.")
        
        # Get geolocation data
        geo_data = self.get_geolocation(ip_address)
        
        # Log the request with geolocation data
        RequestLog.objects.create(
            ip_address=ip_address,
            path=request.path,
            country=geo_data.get('country'),
            city=geo_data.get('city')
        )
        
        return None
