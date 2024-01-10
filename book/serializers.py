from random import random

from django.contrib.auth import get_user_model, password_validation
from django.core.exceptions import ObjectDoesNotExist
from django.template.loader import render_to_string
from rest_framework import serializers, exceptions

from .models import OTP
from ..bookReview.settings import DEFAULT_FROM_EMAIL
from ..utils import sendHtmlEmail


class RegistrationSerializer(serializers.ModelSerializer):
    linkedin = serializers.CharField(max_length=150, required=False, allow_null=True)
    website = serializers.CharField(max_length=150, required=False, allow_null=True)
    position = serializers.CharField(max_length=50, required=False, allow_null=True)
    # referral = serializers.CharField(max_length=50, required=False, allow_null=True)
    email = serializers.EmailField(max_length=150, required=True)
    username = serializers.CharField(max_length=150, required=True)

    class Meta:
        model = get_user_model()
        fields = ('first_name', 'last_name', 'username', 'account_type', 'email', 'password', 'country', 'linkedin',
                  'website', 'position', 'referral')

    def validate_email(self, data):
        try:
            get_user_model().objects.get(email=data, is_active=True)
            raise serializers.ValidationError("Email already exist")
        except ObjectDoesNotExist:
            return data

    def validate_username(self, data):
        try:
            get_user_model().objects.get(email=data, is_active=True)
            raise serializers.ValidationError("Email already exist")
        except ObjectDoesNotExist:
            return data

    def validated_account_type(self, data):
        """
        Method to validate account_type default value is 'Individual'
        :param data:
        :return: data
        """
        if data.lower() not in ("individual", "company"):
            raise serializers.ValidationError()
        else:
            return data.lower()

    def validate_password(self, value):
        try:
            password_validation.validate_password(value)
        except Exception as exc:
            raise serializers.ValidationError(str(exc))
        return value

    def create(self, validated_data):
        email = validated_data['email']
        try:
            user = get_user_model().objects.get(email=email)
            if user.is_active:
                raise serializers.ValidationError()
            else:
                user.delete()
            user = super().create(validated_data)
        except ObjectDoesNotExist:
            user = super().create(validated_data)
        user.set_password(validated_data["password"])
        user.is_active = False
        user.save()
        otp = OTP.objects.get_or_create(user=user, otp_type='register')[0]
        otp.otp = random.randint(100000, 999999)
        otp.save()
        message = render_to_string(
            'email/registraton_otp.html',
            {
                'otp': otp.otp,
                'name': user.first_name
            }
        )
        subject = 'OTP Confirmation for Registration'
        sendHtmlEmail(subject, message, [email], DEFAULT_FROM_EMAIL)
        return user


class LoginSerializer(serializers.ModelSerializer):
    """
    Login serializer.
    """

    class Meta:
        model = get_user_model()
        fields = ('email', 'password')


class ResetPasswordSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    password = serializers.CharField(required=False)
    otp = serializers.CharField(max_length=6, required=False)

    class Meta:
        model = get_user_model()
        fields = ('email', 'password', 'otp')

    def validate_otp(self, value):
        request = self.context.get("request")
        try:
            OTP.objects.get(user=request, otp_type='reset_password', otp=value)
        except ObjectDoesNotExist:
            raise serializers.ValidationError(detail="OTP dose not matched", code=406)
        return value

    def validate_password(self, value):
        try:
            password_validation.validate_password(value)
        except Exception as exc:
            raise serializers.ValidationError(str(exc))
        return value

    def create(self, validated_data):
        email = validated_data['email']
        user = get_user_model().objects.get(email=email)
        otp = OTP.objects.get_or_create(user=user, otp_type='reset_password')[0]
        otp.otp = random.randint(100000, 999999)
        otp.save()
        message = render_to_string(
            'email/reset_password_otp.html',
            {
                'otp': otp.otp,
                'name': user.first_name
            }
        )
        subject = 'OTP Confirmation for Reset Password'
        sendHtmlEmail(subject, message, [email], DEFAULT_FROM_EMAIL)
        return user

    def update(self, instance, validated_data):
        try:
            otp = OTP.objects.get(user=instance, otp_type='reset_password', otp=validated_data['otp'])
        except ObjectDoesNotExist:
            raise exceptions.NotFound(detail="OTP dose not matched", code=406)
        instance.set_password(validated_data["password"])
        instance.save()
        otp.delete()
        return instance
