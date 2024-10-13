from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.template.loader import render_to_string
from django.conf import settings


@login_required(login_url='/login/')
def index(request):
    return render(request, 'app/dashboard.html')


@login_required(login_url='/login/')
def support(request):
    msg = None
    if request.method == "POST":
        # On récupère les informations du formulaire
        subject = request.POST.get("subject")
        message = request.POST.get("message")
        email = request.user.email

        try:

            # On convertit le fichier email en string après avoir remplacé les variables à l'intérieur
            msge = render_to_string(
                "app/support_email.html",
                {
                    "username": request.user.username,
                    "message": message,
                    "subject": subject,
                },
            )

            # On envoi un mail à l'admin avec le message du client
            send_mail(
                subject,
                msge,
                settings.FROM_EMAIL_ADDRESS,
                ['lougbegnona@gmail.com',settings.FROM_EMAIL_ADDRESS],
                fail_silently=False,
            )

            # On envoie un mail au user pour accuser bonne réception de son mail
            send_mail(
                subject,
                "You have sent the message on Restaurant App. This is your mail:" + message,
                settings.FROM_EMAIL_ADDRESS,
                [email],
                fail_silently=False,
            )

            return redirect("support")

        except Exception as e:
            print(e)

    context = {
    }
    return render(request, 'app/support.html', context)