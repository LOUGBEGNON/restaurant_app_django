# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.urls import path
from .views import login_view, register_user
from django.contrib.auth.views import LogoutView
from apps.authentication.views import *


urlpatterns = [
    # path('dashboard/', login_view, name="login"),
    path('login/', login_view, name="login"),
    path('register/', register_user, name="register"),
    path('register/account-activation/<uidb64>/<token>', activate, name="activate"),
    path("registration/account-types/", choice_account, name="choice_account"),
    path("registration/account-type-checking/", start, name="start"),
    path('auth/password_reset', password_reset, name="password_reset"),
    path("logout/", logout_view, name="logout"),
    path("user/profile", user_profile, name="profile"),
]
