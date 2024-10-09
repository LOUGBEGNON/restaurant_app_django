# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.urls import path
from .views import *
from django.contrib.auth.views import LogoutView
from apps.authentication.views import *


urlpatterns = [
    path('dashboard/', index, name="index"),
]
