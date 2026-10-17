from django.contrib.auth import get_user_model
from rest_framework import generics, permissions
from rest_framework.throttling import ScopedRateThrottle
from rest_framework_simplejwt.views import TokenObtainPairView
from scans.models import AuditLog
from .serializers import RegisterSerializer, UserSerializer

User = get_user_model()


def client_ip(request):
    return request.META.get("REMOTE_ADDR")


class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def perform_create(self, s):
        u = s.save()
        AuditLog.objects.create(user=u, action="register", ip=client_ip(self.request))


class LoginView(TokenObtainPairView):
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "auth"

    def post(self, request, *a, **kw):
        resp = super().post(request, *a, **kw)
        if resp.status_code == 200:
            u = User.objects.filter(username=request.data.get("username")).first()
            AuditLog.objects.create(user=u, action="login", ip=client_ip(request))
        return resp


class MeView(generics.RetrieveUpdateAPIView):
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user


class AdminUserList(generics.ListAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAdminUser]
    queryset = User.objects.all().order_by("-date_joined")


class AdminUserDetail(generics.RetrieveUpdateAPIView):
    """Admins can activate/deactivate users via PATCH {"is_active": bool}."""
    permission_classes = [permissions.IsAdminUser]
    queryset = User.objects.all()

    def get_serializer_class(self):
        from rest_framework import serializers

        class S(serializers.ModelSerializer):
            class Meta:
                model = User
                fields = ["id", "is_active"]
        return S
