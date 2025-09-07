from django.db import models
from django.utils import timezone

class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(default=timezone.now)
    path = models.CharField(max_length=500)
    country = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        location = f"{self.city}, {self.country}" if self.city and self.country else "Unknown"
        return f"{self.ip_address} ({location}) - {self.path} - {self.timestamp}"

class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    created_at = models.DateTimeField(default=timezone.now)
    reason = models.CharField(max_length=200, blank=True, null=True)
    
    def __str__(self):
        return self.ip_address

class SuspiciousIP(models.Model):
    ip_address = models.GenericIPAddressField()
    reason = models.CharField(max_length=500)
    detected_at = models.DateTimeField(default=timezone.now)
    request_count = models.IntegerField(default=0)
    is_resolved = models.BooleanField(default=False)
    auto_blocked = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-detected_at']
        unique_together = ['ip_address', 'reason', 'detected_at']
    
    def __str__(self):
        return f"{self.ip_address} - {self.reason} ({self.detected_at.strftime('%Y-%m-%d %H:%M')})"
