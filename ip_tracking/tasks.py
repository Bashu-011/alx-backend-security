from celery import shared_task
from datetime import datetime, timedelta
from django.utils import timezone
from django.db.models import Count
from .models import RequestLog, SuspiciousIP

SENSITIVE_PATHS = ['/admin', '/login']

@shared_task
def detect_anomalies():
    """
    run hourly
    Ips that
      - Exceed 100 requests in the last hour
      - Or access sensitive URLs (/admin, /login)
    """
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)

    #more than 100 requests in the past hour
    frequent_ips = (
        RequestLog.objects
        .filter(timestamp__gte=one_hour_ago)
        .values('ip_address')
        .annotate(request_count=Count('id'))
        .filter(request_count__gt=100)
    )

    for entry in frequent_ips:
        ip = entry['ip_address']
        reason = f"Exceeded 100 requests/hour (made {entry['request_count']})"
        SuspiciousIP.objects.get_or_create(ip_address=ip, defaults={'reason': reason})

    # accessing sensitive paths
    sensitive_logs = RequestLog.objects.filter(path__in=SENSITIVE_PATHS, timestamp__gte=one_hour_ago)
    for log in sensitive_logs:
        reason = f"Accessed sensitive path: {log.path}"
        SuspiciousIP.objects.get_or_create(ip_address=log.ip_address, defaults={'reason': reason})

    print("Detection completed")
