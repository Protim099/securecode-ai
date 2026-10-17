from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from .models import Profile

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["username", "email", "password"]

    def validate_password(self, v):
        validate_password(v)
        return v

    def validate_email(self, v):
        if User.objects.filter(email__iexact=v).exists():
            raise serializers.ValidationError("Email already registered.")
        return v

    def create(self, data):
        user = User.objects.create_user(**data)
        Profile.objects.create(user=user)
        return user


class UserSerializer(serializers.ModelSerializer):
    role = serializers.SerializerMethodField()
    organization = serializers.CharField(source="profile.organization", required=False, allow_blank=True)
    scan_count = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["id", "username", "email", "is_active", "is_staff", "role", "organization", "date_joined", "scan_count"]
        read_only_fields = ["id", "username", "is_staff", "date_joined", "is_active"]

    def get_role(self, u):
        return "admin" if u.is_staff else "user"

    def get_scan_count(self, u):
        return u.scans.count()

    def update(self, instance, data):
        org = data.pop("profile", {}).get("organization")
        instance.email = data.get("email", instance.email)
        instance.save()
        if org is not None:
            p, _ = Profile.objects.get_or_create(user=instance)
            p.organization = org
            p.save()
        return instance
