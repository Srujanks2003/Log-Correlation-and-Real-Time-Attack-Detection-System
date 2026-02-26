from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import LogEntry
from .detectors import (
    detect_bruteforce,
    detect_sql_injection,
    detect_xss,
    detect_directory_traversal,

)


@receiver(post_save, sender=LogEntry)
def run_detection_engine(sender, instance, created, **kwargs):
    if not created:
        return

    detect_bruteforce(instance)
    detect_sql_injection(instance)
    detect_xss(instance)
    detect_directory_traversal(instance)

