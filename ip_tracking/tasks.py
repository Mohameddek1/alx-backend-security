from celery import shared_task
from django.utils import timezone
from django.db.models import Count, Q
from datetime import timedelta
import logging
from .models import RequestLog, SuspiciousIP, BlockedIP

logger = logging.getLogger('ip_tracking')

@shared_task
def detect_anomalies():
    """
    Hourly task to detect suspicious IP activity and flag potential threats.
    
    Detection criteria:
    1. IPs exceeding 100 requests per hour
    2. IPs accessing sensitive paths (/admin, /login, /api/sensitive)
    3. IPs with unusual geographic patterns
    4. IPs with rapid request bursts
    """
    
    # Get time range for the last hour
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)
    
    logger.info(f"Starting anomaly detection for period: {one_hour_ago} to {now}")
    
    # Detection 1: High request volume (>100 requests/hour)
    high_volume_ips = detect_high_volume_requests(one_hour_ago, now)
    
    # Detection 2: Sensitive path access
    sensitive_path_ips = detect_sensitive_path_access(one_hour_ago, now)
    
    # Detection 3: Request pattern anomalies
    pattern_anomaly_ips = detect_pattern_anomalies(one_hour_ago, now)
    
    # Detection 4: Geographic anomalies
    geo_anomaly_ips = detect_geographic_anomalies(one_hour_ago, now)
    
    # Auto-block extremely suspicious IPs
    auto_block_suspicious_ips()
    
    total_flagged = len(high_volume_ips) + len(sensitive_path_ips) + len(pattern_anomaly_ips) + len(geo_anomaly_ips)
    logger.info(f"Anomaly detection completed. Total suspicious IPs flagged: {total_flagged}")
    
    return {
        'period': f"{one_hour_ago} to {now}",
        'high_volume_ips': len(high_volume_ips),
        'sensitive_path_ips': len(sensitive_path_ips),
        'pattern_anomaly_ips': len(pattern_anomaly_ips),
        'geo_anomaly_ips': len(geo_anomaly_ips),
        'total_flagged': total_flagged
    }

def detect_high_volume_requests(start_time, end_time):
    """Detect IPs with more than 100 requests in the last hour."""
    
    high_volume_ips = RequestLog.objects.filter(
        timestamp__range=(start_time, end_time)
    ).values('ip_address').annotate(
        request_count=Count('id')
    ).filter(request_count__gt=100)
    
    flagged_ips = []
    
    for ip_data in high_volume_ips:
        ip_address = ip_data['ip_address']
        count = ip_data['request_count']
        
        # Skip if already flagged recently
        if SuspiciousIP.objects.filter(
            ip_address=ip_address,
            reason__contains='High volume',
            detected_at__gt=timezone.now() - timedelta(hours=6)
        ).exists():
            continue
            
        SuspiciousIP.objects.create(
            ip_address=ip_address,
            reason=f'High volume requests: {count} requests in 1 hour (threshold: 100)',
            request_count=count
        )
        
        flagged_ips.append(ip_address)
        logger.warning(f"High volume detected: {ip_address} made {count} requests")
    
    return flagged_ips

def detect_sensitive_path_access(start_time, end_time):
    """Detect IPs accessing sensitive paths."""
    
    sensitive_paths = ['/admin', '/login', '/api/sensitive', '/password-reset', '/api/login']
    
    sensitive_access_ips = RequestLog.objects.filter(
        timestamp__range=(start_time, end_time),
        path__in=sensitive_paths
    ).values('ip_address', 'path').annotate(
        access_count=Count('id')
    ).filter(access_count__gt=5)  # More than 5 accesses to sensitive paths
    
    flagged_ips = []
    
    for ip_data in sensitive_access_ips:
        ip_address = ip_data['ip_address']
        path = ip_data['path']
        count = ip_data['access_count']
        
        # Skip if already flagged recently
        if SuspiciousIP.objects.filter(
            ip_address=ip_address,
            reason__contains='Sensitive path access',
            detected_at__gt=timezone.now() - timedelta(hours=6)
        ).exists():
            continue
            
        SuspiciousIP.objects.create(
            ip_address=ip_address,
            reason=f'Sensitive path access: {count} attempts to {path}',
            request_count=count
        )
        
        flagged_ips.append(ip_address)
        logger.warning(f"Sensitive path access: {ip_address} accessed {path} {count} times")
    
    return flagged_ips

def detect_pattern_anomalies(start_time, end_time):
    """Detect unusual request patterns (rapid bursts)."""
    
    # Find IPs with requests clustered in short time windows
    suspicious_patterns = RequestLog.objects.filter(
        timestamp__range=(start_time, end_time)
    ).values('ip_address').annotate(
        request_count=Count('id')
    ).filter(request_count__gt=50)
    
    flagged_ips = []
    
    for ip_data in suspicious_patterns:
        ip_address = ip_data['ip_address']
        
        # Check if requests are clustered in short bursts
        recent_requests = RequestLog.objects.filter(
            ip_address=ip_address,
            timestamp__range=(start_time, end_time)
        ).order_by('timestamp')
        
        if recent_requests.count() < 50:
            continue
            
        # Check for burst pattern (many requests in short time)
        first_request = recent_requests.first().timestamp
        last_request = recent_requests.last().timestamp
        duration = (last_request - first_request).total_seconds()
        
        if duration < 300:  # All requests within 5 minutes
            # Skip if already flagged recently
            if SuspiciousIP.objects.filter(
                ip_address=ip_address,
                reason__contains='Burst pattern',
                detected_at__gt=timezone.now() - timedelta(hours=6)
            ).exists():
                continue
                
            SuspiciousIP.objects.create(
                ip_address=ip_address,
                reason=f'Burst pattern: {recent_requests.count()} requests in {duration:.0f} seconds',
                request_count=recent_requests.count()
            )
            
            flagged_ips.append(ip_address)
            logger.warning(f"Burst pattern: {ip_address} made rapid requests")
    
    return flagged_ips

def detect_geographic_anomalies(start_time, end_time):
    """Detect IPs with unusual geographic patterns."""
    
    # Find IPs from countries with high request volumes that are uncommon
    geo_anomalies = RequestLog.objects.filter(
        timestamp__range=(start_time, end_time),
        country__isnull=False
    ).exclude(
        country__in=['US', 'CA', 'GB', 'DE', 'FR', 'Local', 'Unknown']  # Common countries
    ).values('ip_address', 'country').annotate(
        request_count=Count('id')
    ).filter(request_count__gt=20)
    
    flagged_ips = []
    
    for ip_data in geo_anomalies:
        ip_address = ip_data['ip_address']
        country = ip_data['country']
        count = ip_data['request_count']
        
        # Skip if already flagged recently
        if SuspiciousIP.objects.filter(
            ip_address=ip_address,
            reason__contains='Geographic anomaly',
            detected_at__gt=timezone.now() - timedelta(hours=6)
        ).exists():
            continue
            
        SuspiciousIP.objects.create(
            ip_address=ip_address,
            reason=f'Geographic anomaly: {count} requests from uncommon country ({country})',
            request_count=count
        )
        
        flagged_ips.append(ip_address)
        logger.warning(f"Geographic anomaly: {ip_address} from {country} with {count} requests")
    
    return flagged_ips

def auto_block_suspicious_ips():
    """Automatically block IPs that meet extreme criteria."""
    
    # Auto-block IPs with multiple recent suspicious flags
    suspicious_ips = SuspiciousIP.objects.filter(
        detected_at__gt=timezone.now() - timedelta(hours=24),
        is_resolved=False
    ).values('ip_address').annotate(
        flag_count=Count('id')
    ).filter(flag_count__gte=3)  # 3 or more flags in 24 hours
    
    auto_blocked_count = 0
    
    for ip_data in suspicious_ips:
        ip_address = ip_data['ip_address']
        
        # Check if already blocked
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            continue
            
        # Auto-block the IP
        BlockedIP.objects.create(
            ip_address=ip_address,
            reason='Auto-blocked: Multiple suspicious activities detected'
        )
        
        # Mark related suspicious entries as auto-blocked
        SuspiciousIP.objects.filter(
            ip_address=ip_address,
            is_resolved=False
        ).update(auto_blocked=True)
        
        auto_blocked_count += 1
        logger.critical(f"Auto-blocked IP: {ip_address} due to multiple suspicious activities")
    
    return auto_blocked_count

@shared_task
def cleanup_old_suspicious_records():
    """Clean up old suspicious IP records to prevent database bloat."""
    
    # Delete resolved records older than 30 days
    old_resolved = SuspiciousIP.objects.filter(
        is_resolved=True,
        detected_at__lt=timezone.now() - timedelta(days=30)
    )
    
    deleted_count = old_resolved.count()
    old_resolved.delete()
    
    logger.info(f"Cleaned up {deleted_count} old suspicious IP records")
    
    return {'deleted_records': deleted_count}

@shared_task
def generate_security_report():
    """Generate a daily security report with statistics."""
    
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    
    # Collect statistics
    stats = {
        'total_requests_24h': RequestLog.objects.filter(timestamp__gt=last_24h).count(),
        'unique_ips_24h': RequestLog.objects.filter(timestamp__gt=last_24h).values('ip_address').distinct().count(),
        'suspicious_flags_24h': SuspiciousIP.objects.filter(detected_at__gt=last_24h).count(),
        'blocked_ips_total': BlockedIP.objects.count(),
        'auto_blocked_24h': SuspiciousIP.objects.filter(
            detected_at__gt=last_24h,
            auto_blocked=True
        ).count(),
    }
    
    logger.info(f"Security report generated: {stats}")
    
    return stats
