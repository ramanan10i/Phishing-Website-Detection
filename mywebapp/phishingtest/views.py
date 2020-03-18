from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.forms import UserCreationForm
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from . import predict
from phishingtest.models import Url

from .forms import CreateUserForm


@login_required(login_url='phishingtest:Login')
def index(request):
	return render(request,'phishingtest/index.html')

def registerPage(request):
	form = CreateUserForm()

	if request.method == 'POST':
		form = CreateUserForm(request.POST)
		if form.is_valid():
			form.save()
			messages.success(request,'Account created successfully for: ' + form.cleaned_data.get('username'))

			return redirect('phishingtest:Login')


	context = {'form':form}
	return render(request,'phishingtest/register.html',context)

def loginPage(request):

	if request.method == 'POST':
		username = request.POST.get('username')
		password = request.POST.get('password')

		user = authenticate(request,username=username, password=password)

		if user is not None:
			login(request,user)
			return redirect('phishingtest:index')
		else:
			messages.info("Incorrect credentials")

	context = {}
	return render(request,'phishingtest/login.html',context)

def logoutPage(request):
	logout(request)
	return redirect('phishingtest:Login')



@login_required(login_url='phishingtest:Login')
def parser(request):
	if 'url_input' in request.POST:
		url = request.POST.get('url_input')
	else:
		url = None
	try:
		url = Url.objects.get(url_value=url)
		result = url.url_prob
	except:
		result = str(format(predict.predict_result(url),'.5f'))
		urlObj = Url(url_value=url, url_prob=result)
		urlObj.save()
	context = {'result':result}
	return render(request,'phishingtest/prob.html',context)

