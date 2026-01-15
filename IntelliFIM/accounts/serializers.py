from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import User
from django.contrib.auth.password_validation import validate_password
import logging

logger = logging.getLogger(__name__)


class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'password2', 'is_admin')

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields don't match."})
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user


class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        logger.info(f"🔍 Login attempt - Email: {email}")

        user = authenticate(email=email, password=password)

        if not user:
            logger.warning(f"Invalid login attempt for email: {email}")
            raise serializers.ValidationError("Invalid email or password.")

        if not user.is_active:
            raise serializers.ValidationError("Account is disabled.")

        logger.info(f"Login successful - User: {user.username}, Admin: {user.is_admin}")

        attrs['user'] = user
        return attrs


class UserResponseSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'is_admin')
        read_only_fields = fields
