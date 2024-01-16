from django.contrib.auth import get_user_model, password_validation
from django.core.exceptions import ObjectDoesNotExist
from rest_framework import serializers

from .models import UserFollows, Ticket, Review


class RegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ('first_name', 'last_name', 'username', 'password')

    def validate_username(self, data):
        try:
            get_user_model().objects.get(username=data, is_active=True)
            raise serializers.ValidationError("Username already exist")
        except ObjectDoesNotExist:
            return data

    def validate_password(self, value):
        try:
            password_validation.validate_password(value)
        except Exception as exc:
            raise serializers.ValidationError(str(exc))
        return value

    def create(self, validated_data):
        username = validated_data['username']
        try:
            user = get_user_model().objects.get(username=username)
            if user.is_active:
                raise serializers.ValidationError()
            else:
                user.delete()
            user = super().create(validated_data)
        except ObjectDoesNotExist:
            user = super().create(validated_data)
        user.set_password(validated_data["password"])
        user.is_active = True
        user.save()
        return user


class LoginSerializer(serializers.ModelSerializer):
    """
    Login serializer.
    """

    class Meta:
        model = get_user_model()
        fields = ('first_name', 'last_name', 'is_superuser', 'username')


class SubscriberSerializer(serializers.ModelSerializer):
    followed_user = LoginSerializer(read_only=True)

    class Meta:
        model = UserFollows
        fields = ["followed_user", ]


class TicketSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ticket
        fields = ["title", "description", "image"]


class ReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Review
        fields = ["rating", "headline", "body"]
