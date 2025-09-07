from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin
from .models import RequestLog, BlockedIP

class IPTrackingMiddleware(MiddlewareMixin):
    def get_client_ip(self, request):
        """Get the client's IP address, accounting for proxies."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def process_request(self, request):
        # Get client IP address
        ip_address = self.get_client_ip(request)
        
        # Check if IP is blacklisted
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Access denied: Your IP address has been blocked.")
        
        # Log the request
        RequestLog.objects.create(
            ip_address=ip_address,
            path=request.path
        )
        
        return None
