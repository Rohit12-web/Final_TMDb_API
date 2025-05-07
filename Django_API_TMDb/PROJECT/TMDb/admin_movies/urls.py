# admin_movies/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('', views.admin_movie_list, name='admin_movie_list'),
    path('movies/add/', views.add_movie, name='add_movie'),
    path('movies/edit/<int:movie_id>/', views.edit_movie, name='edit_movie'),
    path('movies/delete/<int:movie_id>/', views.delete_movie, name='delete_movie'),
]