# IP Tracking Security System - Production Deployment Guide

This document provides deployment instructions for the comprehensive IP tracking and security monitoring system.

## System Overview

The IP tracking security system includes:
- **IP Logging Middleware**: Captures all incoming requests with geolocation data
- **Rate Limiting**: Protects endpoints from abuse (5 requests/minute default)
- **Anomaly Detection**: Automated hourly scanning for suspicious patterns
- **Background Processing**: Celery tasks for security monitoring and reporting

## Prerequisites

- Python 3.8+
- Redis server (for caching and Celery broker)
- PostgreSQL (recommended for production) or SQLite (development)
- Nginx (for production reverse proxy)

## Quick Development Setup

```bash
# Clone and navigate to project
cd alx-backend-security

# Install dependencies
pip install -r requirements.txt

# Setup environment variables
export REDIS_URL=redis://localhost:6379/0
export CELERY_BROKER_URL=redis://localhost:6379/0
export CELERY_RESULT_BACKEND=redis://localhost:6379/0

# Run setup script
chmod +x run_dev.sh
./run_dev.sh
```

## Production Deployment

### 1. Environment Configuration

```bash
# settings.py production overrides
ALLOWED_HOSTS = ['your-domain.com', 'www.your-domain.com']
DEBUG = False
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
```

### 2. Database Setup

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'security_db',
        'USER': 'security_user',
        'PASSWORD': 'your_secure_password',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
```

### 3. Redis Configuration

```bash
# /etc/redis/redis.conf
maxmemory 256mb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
```

### 4. Celery Production Setup

```bash
# Create systemd service for Celery worker
sudo nano /etc/systemd/system/celery-worker.service

[Unit]
Description=Celery worker for security monitoring
After=network.target

[Service]
Type=notify
User=www-data
Group=www-data
WorkingDirectory=/path/to/alx-backend-security
ExecStart=/path/to/venv/bin/celery -A alx_backend_security worker --loglevel=info
ExecReload=/bin/kill -s HUP $MAINPID
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# Create systemd service for Celery beat
sudo nano /etc/systemd/system/celery-beat.service

[Unit]
Description=Celery beat for scheduled security tasks
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/path/to/alx-backend-security
ExecStart=/path/to/venv/bin/celery -A alx_backend_security beat --loglevel=info
Restart=always

[Install]
WantedBy=multi-user.target
```

### 5. Nginx Configuration

```nginx
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name your-domain.com;
    
    ssl_certificate /path/to/ssl/cert.pem;
    ssl_certificate_key /path/to/ssl/private.key;
    
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /static/ {
        alias /path/to/static/files/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

## API Endpoints

### IP Tracking Logs
```http
GET /api/ip-logs/
Authorization: Token your_api_token

Response:
{
    "count": 1250,
    "results": [
        {
            "ip_address": "192.168.1.100",
            "timestamp": "2024-01-15T10:30:00Z",
            "path": "/api/users/",
            "method": "GET",
            "user_agent": "Mozilla/5.0...",
            "country": "United States",
            "city": "New York"
        }
    ]
}
```

### Suspicious IPs
```http
GET /api/suspicious-ips/
Authorization: Token your_api_token

Response:
{
    "results": [
        {
            "ip_address": "10.0.0.1",
            "detection_type": "high_volume",
            "flagged_at": "2024-01-15T11:00:00Z",
            "is_blocked": true,
            "details": {
                "requests_last_hour": 150,
                "threshold": 100
            }
        }
    ]
}
```

## Monitoring and Alerts

### Security Metrics Dashboard

The system generates hourly security reports including:
- Request volume trends
- Geographic distribution of traffic
- Top suspicious IPs
- Rate limiting effectiveness
- Anomaly detection accuracy

### Log Analysis

```bash
# Monitor real-time security events
tail -f logs/security.log

# View Celery task execution
celery -A alx_backend_security flower --port=5555
# Access dashboard at http://localhost:5555

# Redis monitoring
redis-cli monitor | grep -E "(SET|GET|DEL) (ip_|rate_limit_|geo_)"
```

## Security Best Practices

1. **Regular Updates**: Keep dependencies updated, especially security-related packages
2. **Rate Limit Tuning**: Adjust limits based on legitimate traffic patterns
3. **Geolocation Caching**: Cache geolocation data to reduce API calls
4. **Log Rotation**: Implement log rotation to manage disk space
5. **Backup Strategy**: Regular backups of IP tracking data and suspicious IP lists

## Troubleshooting

### Common Issues

1. **Redis Connection Error**
   ```bash
   # Check Redis status
   redis-cli ping
   # Should return PONG
   ```

2. **Celery Tasks Not Running**
   ```bash
   # Check worker status
   celery -A alx_backend_security inspect active
   # Restart workers
   sudo systemctl restart celery-worker celery-beat
   ```

3. **High Memory Usage**
   ```python
   # Add to settings.py
   CACHES['default']['OPTIONS']['CONNECTION_POOL_KWARGS']['max_connections'] = 50
   ```

4. **Geolocation API Limits**
   ```python
   # Implement fallback in tasks.py
   def get_geolocation(ip_address):
       try:
           # Primary API call
           return primary_geolocation_service(ip_address)
       except Exception:
           # Fallback to cached data or secondary service
           return get_cached_location(ip_address)
   ```

## Performance Optimization

- **Database Indexing**: Ensure indexes on `ip_address` and `timestamp` fields
- **Redis Memory**: Configure appropriate memory limits and eviction policies
- **Celery Concurrency**: Adjust worker concurrency based on server resources
- **Rate Limiting**: Use Redis for distributed rate limiting across multiple servers

## Support and Maintenance

For ongoing maintenance:
1. Monitor system logs daily
2. Review suspicious IP reports weekly
3. Update rate limiting thresholds based on traffic patterns
4. Backup IP tracking data monthly
5. Update geolocation databases quarterly

The system is designed to be self-maintaining with automated cleanup tasks and comprehensive logging for troubleshooting.
