from rest_framework import serializers
from .models import AuditLog, Scan, VulnerabilityFinding


class FindingSerializer(serializers.ModelSerializer):
    file_name = serializers.CharField(source="file.filename", read_only=True)
    ai_generated = serializers.SerializerMethodField()

    class Meta:
        model = VulnerabilityFinding
        exclude = ["file", "scan"]

    def get_ai_generated(self, o):
        return bool(o.ai_suggestion)


class ScanSerializer(serializers.ModelSerializer):
    finding_count = serializers.SerializerMethodField()
    severity_counts = serializers.SerializerMethodField()
    owner = serializers.CharField(source="user.username", read_only=True)

    class Meta:
        model = Scan
        fields = ["id", "title", "language", "status", "created_at", "completed_at", "is_demo", "owner",
                  "finding_count", "severity_counts"]

    def get_finding_count(self, o):
        return len(o.findings.all())

    def get_severity_counts(self, o):
        c = {}
        for f in o.findings.all():
            c[f.severity] = c.get(f.severity, 0) + 1
        return c


class ScanDetailSerializer(ScanSerializer):
    findings = FindingSerializer(many=True, read_only=True)

    class Meta(ScanSerializer.Meta):
        fields = ScanSerializer.Meta.fields + ["findings"]


class AuditSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", default="-", read_only=True)

    class Meta:
        model = AuditLog
        fields = ["id", "username", "action", "detail", "ip", "created_at"]
