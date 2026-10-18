from django.conf import settings
from django.db import models

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]


class Scan(models.Model):
    STATUS = [("pending", "Pending"), ("completed", "Completed"), ("failed", "Failed")]
    LANGS = [("python", "Python"), ("javascript", "JavaScript"), ("java", "Java"), ("php", "PHP")]
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="scans")
    title = models.CharField(max_length=200)
    language = models.CharField(max_length=20, choices=LANGS)
    status = models.CharField(max_length=10, choices=STATUS, default="pending")
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    is_demo = models.BooleanField(default=False)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["user", "-created_at"])]


class ScanFile(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="files")
    filename = models.CharField(max_length=255)
    content = models.TextField()
    size = models.PositiveIntegerField()


class VulnerabilityFinding(models.Model):
    SEV = [(s, s) for s in SEVERITIES]
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="findings")
    file = models.ForeignKey(ScanFile, on_delete=models.CASCADE, related_name="findings")
    rule_id = models.CharField(max_length=60)
    title = models.CharField(max_length=200)
    severity = models.CharField(max_length=10, choices=SEV)
    line = models.PositiveIntegerField()
    evidence = models.TextField(blank=True)
    explanation = models.TextField(blank=True)
    cwe = models.CharField(max_length=20, blank=True)
    owasp = models.CharField(max_length=40, blank=True)
    remediation = models.TextField(blank=True)
    source = models.CharField(max_length=20)  # bandit | rules  (verified static analysis)
    ai_suggestion = models.TextField(blank=True)  # advisory, model-generated
    ai_provider = models.CharField(max_length=20, blank=True)

    class Meta:
        indexes = [models.Index(fields=["scan", "severity"])]


class ScanReport(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="reports")
    fmt = models.CharField(max_length=5)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)


class AuditLog(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=60)
    detail = models.CharField(max_length=255, blank=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
