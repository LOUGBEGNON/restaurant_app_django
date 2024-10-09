# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""
from django.core.mail import send_mail
# Create your views here.
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
import django.contrib.messages as messages
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from .backends import EmailBackend
from .forms import LoginForm, SignUpForm, RegisterForm
import logging
from django.contrib.sites.shortcuts import get_current_site
from apps.utils import get_site_scheme_and_domain
from .tokens import account_activation_token
from django.utils.encoding import force_bytes,force_str as force_text
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth import get_user_model
from apps.authentication.models import *

from ..utils import generate_username
from django.contrib.auth import logout as auth_logout

logger = logging.getLogger("django")

def choice_account(request):
    return render(request, "authentication/choice_account.html")


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
            # username = form.cleaned_data.get("email")
            email = form.cleaned_data.get("email")
            password = form.cleaned_data.get("password")
            print(email)
            print(password)

            email_backend = EmailBackend()
            # user = authenticate(username=email, password=password)
            user = email_backend.authenticate(request, username=email, password=password)
            print(user)
            if user is not None:
                login(request, user, backend="apps.authentication.backends.EmailBackend")
                if user.is_active:
                    print(user)
                    # add the user to the default group(s), if needed
                    # For "individuals", we add them to the community group
                    # if hasattr(user, "individual"):
                    #   # if request.user.individual.municipality:
                    #   #   municipality = Municipality.objects.get(
                    #   #     slug=request.user.individual.municipality_slug
                    #   #   )
                    #   # else:
                    #   #   if user.role == user.INDIVIDUAL:
                    #   #     return redirect("inactive_account")
                    #   #   return redirect("register_municipality")
                    #   #
                    #   # if user.role == user.INDIVIDUAL:
                    #   #   if not user.groups.filter(
                    #   #           name=settings.COMMUNITY_GROUP
                    #   #   ).exists():
                    #   #     grp = Group.objects.get(name=settings.COMMUNITY_GROUP)
                    #   #     grp.user_set.add(user)
                    #   #   return redirect(
                    #   #     reverse(
                    #   #       "home",
                    #   #       kwargs={"municipality_slug": municipality.slug},
                    #   #     )
                    #   #   )
                    #   # elif user.role == user.MUNICIPALITY:
                    #   #   return redirect(
                    #   #     reverse(
                    #   #       "home",
                    #   #       kwargs={"municipality_slug": municipality.slug},
                    #   #     )
                    #   #   )
                    #   # elif user.role == user.COMPANY:
                    #   #   return redirect(
                    #   #     reverse(
                    #   #       "home",
                    #   #       kwargs={"municipality_slug": municipality.slug},
                    #   #     )
                    #   #   )
                    #   pass
                    # else:
                    #   return redirect("register_individual")
                    print("Je suis bien connecté et je suis redirigé")
                    return redirect("index")
                else:
                    msg = "Please confirm your email before logging in."
                    print(msg)
                    messages.error(request, msg)
                return redirect("index")
            else:
                msg = 'Invalid credentials'
                print('fnbdvghfv')
                print(msg)
        else:
            msg = 'Error validating the form'

    return render(request, "authentication/login.html", {"form": form, "msg": msg})


def register_user(request):
    msg = None
    success = False
    if "type_account" in request.GET:
        type_account = request.GET.get("type_account")
    else:
        type_account = "user"

    print(type_account)

    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            # form.save()
            user = form.save(commit=False)
            user.is_active = False
            user.first_login = True

            username = form.cleaned_data.get("username")
            raw_password = form.cleaned_data.get("password1")
            # user = authenticate(username=username, password=raw_password)

            msg = 'User created - please <a href="/login">login</a>.'
            success = True

            to_email = form.cleaned_data.get("email")

            if type_account == "customer":
                user.role = user.CUSTOMER
            elif type_account == "staff":
                user.role = user.STAFF
            elif type_account == "owner":
                user.role = user.OWNER

            user.username = generate_username(to_email)

            user.save()
            print('Account created successfully!')
            logger.info(f"User model {user.id} saved")

            # Send verification mail. Handle any exception that could occur.
            try:
                verify_email(user, request)
                logger.info(f"Send verification email for {user.username}")
                logger.info(f"Send New User {user.username} notification to Project...")

                send_mail(
                    user.username + " registered to Restaurant App",
                    "A new user ("
                    + user.username
                    + ") with email "
                    + " has registered to Restaurant App",
                    "amedeelougbegnon3@gmail.com",
                    ['lougbegnona@gmail.com'],
                    fail_silently=False,
                )

                return redirect('/login/')
            except Exception as e:
                print(e)
                logger.error(f"Error sending the verification message: {e}")

            return redirect("/login/")

        else:
            msg = 'Form is not valid'
            print(form.errors)
    else:
        form = RegisterForm()

    context = {
        "form": form,
        "msg": msg,
        "success": success
    }

    return render(request, "authentication/register.html", context)


def verify_email(user, request):
    """Send verification mail"""
    # from apps.authentication.views.utils import get_site_scheme_and_domain

    site_domain = get_current_site(request)

    from_email = (
            "Restaurant App <" + "amedeelougbegnon3@gmail.com" + ">"
    )
    mail_subject = "Account Registration Confirmation"
    to_email = user.email

    msge = render_to_string(
      "authentication/acc_active_email.txt",
      {
        "username": user.username,
        "url": reverse(
          "activate",
          kwargs={
            "uidb64": urlsafe_base64_encode(force_bytes(user.pk)),
            "token": account_activation_token.make_token(user),
          },
        ),
        "domain": site_domain,
        "scheme": "http",
      },
    )

    msge_html = render_to_string(
      "authentication/acc_active_email.html",
      {
        "username": user.username,
        "url": reverse(
          "activate",
          kwargs={
            "uidb64": urlsafe_base64_encode(force_bytes(user.pk)),
            "token": account_activation_token.make_token(user),
          },
        ),
        "domain": site_domain,
        "scheme": "http",
      },
    )
    send_mail(
      mail_subject,
      msge,
      from_email,
      [to_email],
      fail_silently=False,
      html_message=msge_html,
    )

def user_profile(request):
    context = {

    }
    return render(request,"authentication/profile.html", context)



def password_reset(request):
    return render(request,"authentication/page-forgot-password.html" )

def activate(request, uidb64, token):
    response = None
    try:
      uid = force_text(urlsafe_base64_decode(uidb64))
      user = get_user_model().objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
      user = None
    if user is not None and account_activation_token.check_token(user, token):
      user.is_active = True
      user.save()
      response = "Thank you for confirming your email. Your account has been activated."
    return render(
      request,
      "authentication/account_activation_status.html",
      {"response": response},
    )


def logout_view(request):
    auth_logout(request)
    response = redirect("login")
    return response