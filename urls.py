from django.urls import path
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register("scans", views.ScanViewSet, basename="scan")
urlpatterns = router.urls + [
    path("findings/<int:pk>/explain/", views.explain_finding),
    path("stats/", views.stats),
    path("admin/audit/", views.AuditList.as_view()),
]
