from django.db import models
from django.conf import settings


class NetworkAlert(models.Model):
    SEVERITY_CHOICES = [
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
    ]

    timestamp = models.DateTimeField(auto_now_add=True)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    destination_ip = models.GenericIPAddressField(null=True, blank=True)
    protocol = models.CharField(max_length=20, null=True, blank=True)
    description = models.TextField()
    packet_data = models.JSONField(default=dict, null=True, blank=True)
    resolved = models.BooleanField(default=False)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['severity']),
        ]

    def __str__(self):
        return f"{self.timestamp} - {self.severity}: {self.description[:50]}"


class NetworkStatistic(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    interface = models.CharField(max_length=50)
    total_packets = models.BigIntegerField(default=0)
    total_bytes = models.BigIntegerField(default=0)
    bandwidth_mbps = models.FloatField(default=0.0)
    packet_types = models.JSONField(default=dict)
    uptime_seconds = models.FloatField(default=0.0)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.timestamp} - {self.interface}: {self.bandwidth_mbps:.2f} Mbps"
