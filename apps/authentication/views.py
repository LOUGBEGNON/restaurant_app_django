# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

# Create your views here.
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from .forms import LoginForm, SignUpForm
import logging


logger = logging.getLogger("django")

def choice_account(request):
    return render(request, "authentication/register_common/choice_account.html")


# @redir_if_authenticated(redir_url_name="home")
def start(request):
    if "type_account" in request.GET:
        type_account = request.GET.get("type_account")
    else:
        type_account = "customer"

    logger.info(f"Start registration for {type_account}")
    request.session["type_account"] = type_account

    return redirect("confidentiality")


def login_view(request):
    form = LoginForm(request.POST or None)

    msg = None

    if request.method == "POST":

        if form.is_valid():
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password")
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect("/")
            else:
                msg = 'Invalid credentials'
        else:
            msg = 'Error validating the form'

    return render(request, "authentication/login.html", {"form": form, "msg": msg})


def register_user(request):
    msg = None
    success = False

    if request.method == "POST":
        form = SignUpForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get("username")
            raw_password = form.cleaned_data.get("password1")
            user = authenticate(username=username, password=raw_password)

            msg = 'User created - please <a href="/login">login</a>.'
            success = True

            # return redirect("/login/")

        else:
            msg = 'Form is not valid'
    else:
        form = SignUpForm()

    return render(request, "authentication/register.html", {"form": form, "msg": msg, "success": success})


def password_reset(request):
    return render(request,"authentication/page-forgot-password.html" )
