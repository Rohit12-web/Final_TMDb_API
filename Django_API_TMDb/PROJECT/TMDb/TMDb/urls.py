"""
URL configuration for TMDb project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
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


from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth import views as auth_views
from app1 import views as user_views 
urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('app1.urls')), 
    path('admin-custom/', include('admin_movies.urls')),
    
    path('login/', auth_views.LoginView.as_view(template_name='app1/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(template_name='app1/logout.html'), name='logout'),
    path('register/', user_views.register_view, name='register'),
]
# In your project's urls.py





