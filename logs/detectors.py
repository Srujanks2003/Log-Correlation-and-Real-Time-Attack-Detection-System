from datetime import timedelta
from django.db.models import Count
from .models import LogEntry, Alert
from django.utils import timezone


print("Detectors loaded successfully")


# ------------------------Prevent duplicate alerts (time controlled)----------------------------------------

def create_alert(ip, alert_type, message, severity):
    recent_window = timezone.now() - timedelta(minutes=10)

    existing = Alert.objects.filter(
        ip_address=ip,
        alert_type=alert_type,
        is_resolved=False,
        created_at__gte=recent_window
    ).exists()

    if not existing:
        Alert.objects.create(
            ip_address=ip,
            alert_type=alert_type,
            message=message,
            severity=severity
        )


# --------------------Brute Force Detection-------------------------

def detect_bruteforce(instance):

    if instance.status_code not in [401, 403]:
        return

    now = timezone.now()
    ten_minutes_ago = now - timedelta(minutes=10)

    recent_failures = LogEntry.objects.filter(
        ip_address=instance.ip_address,
        status_code__in=[401, 403],
        timestamp__gte=ten_minutes_ago,
        timestamp__lte=now
    ).count()

    total_failures = LogEntry.objects.filter(
        ip_address=instance.ip_address,
        status_code__in=[401, 403]
    ).count()

    if total_failures >= 15:
        create_alert(
            instance.ip_address,
            "Repeated Brute Force Attacker",
            f"Total failed attempts across uploads: {total_failures}",
            "High"
        )

    elif recent_failures >= 5:
        create_alert(
            instance.ip_address,
            "Brute Force Attempt (Burst)",
            f"{recent_failures} failed attempts within 10 minutes",
            "Medium"
        )


# -------------------- SQL Injection---------------------------

def detect_sql_injection(instance):

    url_lower = instance.url.lower()

    if "or 1=1" in url_lower or "select" in url_lower:

        total_sql = LogEntry.objects.filter(
            ip_address=instance.ip_address,
            url__icontains="or 1=1"
        ).count()

        if total_sql >= 3:
            severity = "High"
            alert_type = "Repeated SQL Injection Attacker"
            message = f"Repeated SQL injection attempts detected ({total_sql} times)."
        else:
            severity = "Medium"
            alert_type = "SQL Injection Attempt"
            message = "SQL injection pattern detected."

        create_alert(
            instance.ip_address,
            alert_type,
            message,
            severity
        )


# ----------------- XSS Detection-------------------------------


def detect_xss(instance):

    url_lower = instance.url.lower()

    if "<script>" in url_lower or "alert(" in url_lower:

        total_xss = LogEntry.objects.filter(
            ip_address=instance.ip_address,
            url__icontains="<script>"
        ).count()

        if total_xss >= 3:
            severity = "High"
            alert_type = "Repeated XSS Attacker"
            message = f"Repeated XSS attempts detected ({total_xss} times)."
        else:
            severity = "Medium"
            alert_type = "XSS Attempt"
            message = "Cross-Site Scripting pattern detected."

        create_alert(
            instance.ip_address,
            alert_type,
            message,
            severity
        )


# --------------------Directory Traversal----------------------------

def detect_directory_traversal(instance):
    if "../" in instance.url or "..\\" in instance.url:
        create_alert(
            instance.ip_address,
            "Directory Traversal Attempt",
            f"Traversal pattern detected: {instance.url}",
            "Medium"
        )