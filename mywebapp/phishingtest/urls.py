from django.urls import path

from . import views

app_name='phishingtest'

urlpatterns = [

	path('register/', views.registerPage, name="register"),
	path('login/', views.loginPage, name="Login"),
	path('logout/', views.logoutPage, name="logout"),	

	path('',views.index, name="index"),
	path('parser/',views.parser,name="parser")

	]