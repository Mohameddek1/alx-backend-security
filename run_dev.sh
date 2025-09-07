# Development environment setup script for IP tracking security system

echo "=== IP Tracking Security System - Development Setup ==="
echo "Setting up Redis server, Celery workers, and Django development environment"

echo "Step 1: Starting Redis server (required for caching and Celery broker)"
redis-server --daemonize yes --port 6379

echo "Step 2: Running Django migrations"
python manage.py makemigrations
python manage.py makemigrations ip_tracking
python manage.py migrate

echo "Step 3: Creating superuser (optional)"
echo "from django.contrib.auth.models import User; User.objects.create_superuser('admin', 'admin@example.com', 'admin123') if not User.objects.filter(username='admin').exists() else None" | python manage.py shell

echo "Step 4: Starting Celery worker (background task processor)"
celery -A alx_backend_security worker --loglevel=info --detach --logfile=celery_worker.log

echo "Step 5: Starting Celery beat (task scheduler)"
celery -A alx_backend_security beat --loglevel=info --detach --logfile=celery_beat.log

echo "Step 6: Running Django development server"
echo "Server will start at http://127.0.0.1:8000"
echo "API endpoints available:"
echo "  - GET /api/ip-logs/ - View IP tracking logs"
echo "  - GET /api/suspicious-ips/ - View flagged suspicious IPs"
echo "  - GET /api/rate-limited-view/ - Test rate limiting (5 requests per minute)"
echo ""
echo "To monitor the system:"
echo "  - tail -f celery_worker.log (view worker logs)"
echo "  - tail -f celery_beat.log (view scheduler logs)"
echo "  - redis-cli monitor (view Redis operations)"
echo ""

python manage.py runserver
