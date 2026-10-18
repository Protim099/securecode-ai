import os
import re
from django.conf import settings
from django.http import HttpResponse
from django.utils import timezone
from rest_framework import mixins, permissions, status, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.decorators import action
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from accounts.views import client_ip
from . import ai, reports
from .models import AuditLog, Scan, ScanFile, ScanReport, VulnerabilityFinding
from .scanner import EXT, analyze
from .serializers import AuditSerializer, FindingSerializer, ScanDetailSerializer, ScanSerializer


def safe_name(name):
    return re.sub(r"[^\w.\-]", "_", os.path.basename(name or ""))[:100] or "upload"


class ScanViewSet(mixins.CreateModelMixin, mixins.ListModelMixin, mixins.RetrieveModelMixin,
                  mixins.DestroyModelMixin, viewsets.GenericViewSet):
    def get_queryset(self):
        qs = Scan.objects.select_related("user").prefetch_related("findings__file")
        return qs if self.request.user.is_staff else qs.filter(user=self.request.user)  # no IDOR

    def get_serializer_class(self):
        return ScanDetailSerializer if self.action == "retrieve" else ScanSerializer

    def get_throttles(self):
        if self.action == "create":
            t = ScopedRateThrottle()
            t.scope = "scan"
            return [t]
        return super().get_throttles()

    def create(self, request, *a, **kw):
        lang = request.data.get("language", "python")
        if lang not in EXT:
            return Response({"error": "Unsupported language."}, status=400)
        up = request.FILES.get("file")
        if up:
            name = safe_name(up.name)
            if not name.lower().endswith(EXT[lang]):
                return Response({"error": f"File must end with {EXT[lang]}."}, status=400)
            if up.size > settings.MAX_UPLOAD_BYTES:
                return Response({"error": "File too large."}, status=400)
            code = up.read().decode("utf-8", errors="replace")
        else:
            code, name = request.data.get("code", ""), f"input{EXT[lang]}"
        if not code.strip():
            return Response({"error": "No code provided."}, status=400)
        if len(code.encode("utf-8")) > settings.MAX_UPLOAD_BYTES:
            return Response({"error": "Code too large."}, status=400)

        scan = Scan.objects.create(user=request.user, title=(request.data.get("title") or name)[:200], language=lang)
        sf = ScanFile.objects.create(scan=scan, filename=name, content=code, size=len(code.encode()))
        try:
            found = analyze(code, lang)
            VulnerabilityFinding.objects.bulk_create([VulnerabilityFinding(scan=scan, file=sf, **f) for f in found])
            scan.status = "completed"
        except Exception:
            scan.status = "failed"
        scan.completed_at = timezone.now()
        scan.save()
        AuditLog.objects.create(user=request.user, action="scan", detail=f"scan {scan.id}", ip=client_ip(request))
        scan = self.get_queryset().get(pk=scan.pk)
        return Response(ScanDetailSerializer(scan).data, status=201)

    @action(detail=True, methods=["get"])
    def report(self, request, pk=None):
        scan = self.get_object()
        kind = request.query_params.get("type", "csv")
        if kind not in ("csv", "pdf"):
            return Response({"error": "type must be csv or pdf"}, status=400)
        data = reports.to_csv(scan) if kind == "csv" else reports.to_pdf(scan)
        ScanReport.objects.create(scan=scan, fmt=kind, created_by=request.user)
        ctype = "text/csv" if kind == "csv" else "application/pdf"
        resp = HttpResponse(data, content_type=ctype)
        resp["Content-Disposition"] = f'attachment; filename="scan_{scan.id}.{kind}"'
        return resp


@api_view(["POST"])
def explain_finding(request, pk):
    qs = VulnerabilityFinding.objects.select_related("scan")
    if not request.user.is_staff:
        qs = qs.filter(scan__user=request.user)
    f = qs.filter(pk=pk).first()
    if not f:
        return Response(status=404)
    f.ai_suggestion, f.ai_provider = ai.suggest_fix(f)
    f.save()
    return Response(FindingSerializer(f).data)


@api_view(["GET"])
def stats(request):
    qs = VulnerabilityFinding.objects.filter(scan__user=request.user)
    scans = Scan.objects.filter(user=request.user)
    sev, lang = {}, {}
    for f in qs.values_list("severity", flat=True):
        sev[f] = sev.get(f, 0) + 1
    for l in scans.values_list("language", flat=True):
        lang[l] = lang.get(l, 0) + 1
    return Response({"total_scans": scans.count(), "total_findings": qs.count(), "by_severity": sev,
                     "by_language": lang, "recent": ScanSerializer(scans.prefetch_related("findings")[:5], many=True).data})


class AuditList(ListAPIView):
    serializer_class = AuditSerializer
    permission_classes = [permissions.IsAdminUser]
    queryset = AuditLog.objects.select_related("user")[:200]
