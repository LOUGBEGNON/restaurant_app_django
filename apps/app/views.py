from django.shortcuts import render
from django.contrib.auth.decorators import login_required


@login_required(login_url='/login/')
def index(request):
    return render(request, 'app/dashboard.html')
@login_required(login_url='/login/')
def support(request):
    return render(request, 'app/support.html')