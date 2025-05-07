# Create your views here.
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import user_passes_test
from django.contrib import messages
from app1.models import Movie
from .forms import MovieForm
from django.utils.text import slugify
import datetime

# Check if user is an admin
def is_admin(user):
    return user.is_authenticated and user.is_staff

@user_passes_test(is_admin)
def admin_movie_list(request):
    movies = Movie.objects.all().order_by('-created_at')
    return render(request, 'movie_list.html', {'movies': movies})

@user_passes_test(is_admin)
def add_movie(request):
    if request.method == 'POST':
        form = MovieForm(request.POST)
        if form.is_valid():
            movie = form.save()
            messages.success(request, f"Movie '{movie.title}' added successfully!")
            return redirect('admin_movie_list')
    else:
        # Default to today's date for release_date
        form = MovieForm(initial={'release_date': datetime.date.today()})
    
    return render(request, 'movie_form.html', {'form': form, 'action': 'Add'})

@user_passes_test(is_admin)
def edit_movie(request, movie_id):
    movie = get_object_or_404(Movie, id=movie_id)
    
    if request.method == 'POST':
        form = MovieForm(request.POST, instance=movie)
        if form.is_valid():
            form.save()
            messages.success(request, f"Movie '{movie.title}' updated successfully!")
            return redirect('admin_movie_list')
    else:
        form = MovieForm(instance=movie)
    
    return render(request, 'movie_form.html', {'form': form, 'movie': movie, 'action': 'Edit'})

@user_passes_test(is_admin)
def delete_movie(request, movie_id):
    movie = get_object_or_404(Movie, id=movie_id)
    
    if request.method == 'POST':
        movie_title = movie.title
        movie.delete()
        messages.success(request, f"Movie '{movie_title}' deleted successfully!")
        return redirect('admin_movie_list')
    
    return render(request, 'confirm_delete.html', {'movie': movie})