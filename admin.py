from django.contrib import admin
from .models import Scan, ScanFile, VulnerabilityFinding, ScanReport, AuditLog
for m in (Scan, ScanFile, VulnerabilityFinding, ScanReport, AuditLog):
    admin.site.register(m)
