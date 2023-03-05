# -*- coding: utf-8 -*-
from django.contrib.auth import get_user_model
from rest_framework import serializers
from utils.upload import get_presigned_url

from ihrd.settings import BASIC_IMAGE_URL


class RegisterSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(max_length=200)
    last_name = serializers.CharField(max_length=200)
    username = serializers.CharField(max_length=200)
    phone_number = serializers.CharField(max_length=200)

    class Meta:
        model = get_user_model()
        fields = (
            "email",
            "first_name",
            "last_name",
            "phone_number",
            "password",
            "username",
        )


class LoginSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=200)
    email = serializers.CharField(max_length=200)

    class Meta:
        model = get_user_model()
        fields = ("email", "password")


class UserSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField()
    first_name = serializers.CharField(max_length=200)
    last_name = serializers.CharField(max_length=200)
    username = serializers.CharField(max_length=200)
    phone_number = serializers.CharField(max_length=200)
    department = serializers.CharField(max_length=300)
    image_name = serializers.CharField(max_length=300)
    image_url = serializers.SerializerMethodField("_image_url")

    def _image_url(self, obj):
        if obj.image_url:
            if str(obj.image_url).startswith("user_images/"):
                return BASIC_IMAGE_URL + str(obj.image_url)
            elif obj.image_name:
                return get_presigned_url(obj.image_name)
            else:
                return str(obj.image_url)
        else:
            return None

    class Meta:
        model = get_user_model()
        fields = (
            "id",
            "email",
            "first_name",
            "last_name",
            "phone_number",
            "username",
            "department",
            "image_name",
            "image_url",
        )


class ResetPasswordSerializer(serializers.Serializer):

    password = serializers.CharField(max_length=200)
    token = serializers.CharField(max_length=1000)



class UserNotesSerializer(serializers.Serializer):
    note_text = serializers.CharField()
    id = serializers.IntegerField()
    is_edited = serializers.BooleanField()
    created_at = serializers.DateTimeField()
    updated_at = serializers.DateTimeField()





class EmptySerializer(serializers.Serializer):
    pass

