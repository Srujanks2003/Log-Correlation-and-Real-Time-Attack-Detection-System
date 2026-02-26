from django.db import models
import hashlib

class LogEntry(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField()
    method = models.CharField(max_length=10)
    url = models.TextField()
    status_code = models.IntegerField()
    response_size = models.IntegerField()

    def __str__(self):
        return f"{self.ip_address} - {self.status_code}"


# ----------------------------------------------------------------------------------------------
# ALERT CREATION

class Alert(models.Model):
    SEVERITY_CHOICES = [
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
    ]

    ip_address = models.GenericIPAddressField()
    alert_type = models.CharField(max_length=100)
    message = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='Medium')
    is_resolved = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip_address} - {self.alert_type} ({self.severity})"
