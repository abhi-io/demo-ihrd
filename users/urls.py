# -*- coding: utf-8 -*-
"""djangobasics URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import include
from django.urls import path
from rest_framework.routers import DefaultRouter


from .views import ChangePasswordViewSet

from .views import ForgotPasswordViewSet
from .views import LoginViewSet
from .views import LogoutViewSet
from .views import RegisterViewSet
from .views import ResetPasswordViewSet
from .views import UploadImageViewSet
from .views import UserNotesViewSet
from .views import UserViewSet

router = DefaultRouter(trailing_slash=False)

router.register(r"register", RegisterViewSet, basename="register")
router.register(r"login", LoginViewSet, basename="login")
router.register(r"user", UserViewSet, basename="user")
router.register(r"logout", LogoutViewSet, basename="logout")
router.register(r"forgot-password", ForgotPasswordViewSet, basename="forgot-password")
router.register(r"reset-password", ResetPasswordViewSet, basename="reset-password")
router.register(r"image-upload", UploadImageViewSet, basename="image-upload")
router.register(r"change-password", ChangePasswordViewSet, basename="change-password")
router.register(r"user-note", UserNotesViewSet, basename="user-note")
urlpatterns = [
    path(r"", include(router.urls)),
]
