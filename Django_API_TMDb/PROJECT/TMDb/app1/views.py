from django.shortcuts import render, redirect, get_object_or_404

from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.conf import settings
from django.utils.timezone import now
import json
import os
import datetime
from openai import OpenAI
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.urls import reverse_lazy
from django.views import generic
from .models import Movie, WatchlistItem,Newsletter,JattJulietReview
from admin_movies.forms import MovieForm # You'll need to create this or move it from admin_movies
from django import forms
from django.contrib.auth.models import User
from .forms import ContactForm,NewsletterForm

from django.http import HttpResponseRedirect
from django.http import HttpResponse

import requests
from django.shortcuts import render



def ratings_view(request):
    response = requests.get("http://127.0.0.1:5000/api/ratings")  # Flask rating API
    ratings = response.json() if response.status_code == 200 else []
    return render(request, "ratings.html", {"ratings": ratings})
import requests
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test



# Contact views
def contact_form(request):
    """Display the contact form page for users to submit messages"""
    return render(request, "contact_form.html")


def contacts_list(request):
    """Display all submitted contacts (admin only)"""
    try:
        # Add timeout to prevent hanging if Flask server is down
        response = requests.get("http://127.0.0.1:5000/api/contacts", timeout=5)
        
        if response.status_code == 200:
            contacts = response.json()
            print(f"Successfully retrieved {len(contacts)} contacts")  # Debug print
            return render(request, "contacts_list.html", {"contacts": contacts})
        else:
            error_message = f"API returned status code: {response.status_code}"
            print(f"API error: {error_message}")  # Debug print
            messages.error(request, f"Failed to load contacts: {error_message}")
            return render(request, "contacts_list.html", {"contacts": [], "api_error": error_message})
    
    except Exception as e:
        print(f"Exception in contacts_list view: {str(e)}")  # Debug print
        messages.error(request, f"An unexpected error occurred: {str(e)}")
        return render(request, "contacts_list.html", {"contacts": [], "api_error": str(e)})

# Step 3: Add similar error handling to other Flask-dependent views
def contact_detail(request, contact_id):
    """Display a single contact's details (admin only)"""
    try:
        response = requests.get(f"http://127.0.0.1:5000/api/contacts/{contact_id}", timeout=5)
        
        if response.status_code == 200:
            contact = response.json()
            return render(request, "contact_detail.html", {"contact": contact})
        elif response.status_code == 404:
            messages.error(request, "Contact not found in the API")
            return redirect("contacts_list")
        else:
            messages.error(request, f"API error (status code: {response.status_code})")
            return redirect("contacts_list")
    
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        messages.error(request, f"Could not connect to the API server: {str(e)}")
        return redirect("contacts_list")
    
    except Exception as e:
        messages.error(request, f"An unexpected error occurred: {str(e)}")
        return redirect("contacts_list")

def submit_contact(request):
    """Handle contact form submissions"""
    if request.method == "POST":
        data = {
            "name": request.POST.get("name"),
            "email": request.POST.get("email"),
            "mobile_no": request.POST.get("mobile_no"),
            "message": request.POST.get("message")
        }
        
        # Validate required fields
        if not all(data.values()):
            messages.error(request, "All fields are required")
            return render(request, "contact_form.html", {"form_data": data})
        
        response = requests.post("http://127.0.0.1:5000/api/contacts", json=data)
        
        if response.status_code == 201:
            messages.success(request, "Your message has been submitted successfully!")
            return redirect("contact_form")
        else:
            error_msg = response.json().get("error", "Failed to submit contact") if response.content else "Failed to submit contact"
            messages.error(request, error_msg)
            return render(request, "contact_form.html", {"form_data": data})
    
    return redirect("contact_form")

def delete_contact(request, contact_id):
    if request.method == "POST":
        try:
            response = requests.delete(f"http://127.0.0.1:5000/api/contacts/{contact_id}", timeout=5)
            if response.status_code == 200:
                messages.success(request, "Contact deleted successfully.")
            elif response.status_code == 404:
                messages.error(request, "Contact not found.")
            else:
                messages.error(request, f"Failed to delete contact (Status code: {response.status_code}).")
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            messages.error(request, f"API connection error: {str(e)}")
        except Exception as e:
            messages.error(request, f"An unexpected error occurred: {str(e)}")
    
    return redirect("contacts_list")




def subscribe_newsletter(request):
    if request.method == 'POST':
        email = request.POST.get('email', '')
        if email:
            # Create or get the subscription
            obj, created = Newsletter.objects.get_or_create(email=email)
            if created:
                messages.success(request, "Thanks for subscribing!")
            else:
                messages.info(request, "You're already subscribed!")
        return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))


class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2")

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user

# Function-based register view (recommended approach)
def register_view(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            messages.success(request, f"Account created for {username}! You can now log in.")
            return redirect('login')
    else:
        form = CustomUserCreationForm()
    return render(request, 'registration.html', {'form': form})

# Function-based login view
def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, f"Welcome back, {username}!")
                return redirect('home')  # Redirect to homepage after login
            else:
                messages.error(request, "Invalid username or password.")
        else:
            messages.error(request, "Invalid username or password.")
    else:
        form = AuthenticationForm()
    return render(request, 'login.html', {'form': form})

# Function-based logout view
def logout_view(request):
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect('home')
    



# Check if user is an admin
def is_admin(user):
    return user.is_authenticated and user.is_staff


@user_passes_test(is_admin)
def admin_movie_list(request):
    movies = Movie.objects.all().order_by('-created_at')
    return render(request, 'admin_movies/movie_list.html', {'movies': movies})


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
    
    return render(request, 'admin_movies/movie_form.html', {'form': form, 'action': 'Add'})


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
    
    return render(request, 'admin_movies/movie_form.html', {'form': form, 'movie': movie, 'action': 'Edit'})


@user_passes_test(is_admin)
def delete_movie(request, movie_id):
    movie = get_object_or_404(Movie, id=movie_id)
    
    if request.method == 'POST':
        movie_title = movie.title
        movie.delete()
        messages.success(request, f"Movie '{movie_title}' deleted successfully!")
        return redirect('admin_movie_list')
    
    return render(request, 'admin_movies/confirm_delete.html', {'movie': movie})


@login_required
def toggle_watchlist(request, movie_id):
    movie = get_object_or_404(Movie, id=movie_id)
    
    # Check if movie is already in watchlist
    watchlist_item = WatchlistItem.objects.filter(user=request.user, movie=movie).first()
    
    if watchlist_item:
        # Remove from watchlist
        watchlist_item.delete()
        in_watchlist = False
        message = f"'{movie.title}' removed from your watchlist."
    else:
        # Add to watchlist
        WatchlistItem.objects.create(user=request.user, movie=movie)
        in_watchlist = True
        message = f"'{movie.title}' added to your watchlist."
    
    # If AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({
            'status': 'success',
            'in_watchlist': in_watchlist,
            'message': message
        })
    
    # If regular request
    messages.success(request, message)
    return redirect('watchlist')


def view_watchlist(request):
    if not request.user.is_authenticated:
        return render(request, '404.html')
    
    watchlist_items = WatchlistItem.objects.filter(user=request.user).select_related('movie')
    return render(request, 'watchlist.html', {
        'watchlist_items': watchlist_items
    })



from .models import MovieRating
from .forms import MovieRatingForm
from django.http import Http404
@login_required



def rate_movie(request):
    if request.method == 'POST':
        form = MovieRatingForm(request.POST)
        movie_id = request.POST.get('movie_id')
        
        # Check if movie_id is valid before proceeding
        if not movie_id:
            messages.error(request, "Movie ID is missing")
            return HttpResponseRedirect(request.META.get('HTTP_REFERER', 'card1'))
        
        try:
            # Convert to integer to validate it's a number
            movie_id = int(movie_id)
        except ValueError:
            messages.error(request, "Invalid movie ID format")
            return HttpResponseRedirect(request.META.get('HTTP_REFERER', 'card1'))
            
        if form.is_valid():
            try:
                # Try to get existing rating or create new one
                rating, created = MovieRating.objects.update_or_create(
                    user=request.user,
                    movie_id=movie_id,
                    defaults={'rating': form.cleaned_data['rate']}
                )
                if created:
                    messages.success(request, "Your rating has been submitted!")
                else:
                    messages.success(request, "Your rating has been updated!")
            except Exception as e:
                messages.error(request, f"An error occurred: {str(e)}")
        else:
            messages.error(request, "Please select a valid rating (1-5)")
            
        # Redirect back to the same page
        return HttpResponseRedirect(request.META.get('HTTP_REFERER', 'card1'))
    else:
        # For GET requests, show 404 instead of trying to render a template
        raise Http404("Rate movie page cannot be accessed directly")


def movie_detail(request, movie_id):
    # Your existing movie detail view code
    
    # Get user's current rating for this movie if logged in
    user_rating = None
    if request.user.is_authenticated:
        try:
            user_rating = MovieRating.objects.get(user=request.user, movie_id=movie_id)
        except MovieRating.DoesNotExist:
            pass
    
    context = {
        'movie': movie_id,  # Replace with actual movie object
        'user_rating': user_rating,
        # other context variables
    }
    
    return render(request, 'card1.html', context)







def home3(request):
    # Use more dynamic date filtering
    current_month = now().month
    
    coming_this_month = Movie.objects.filter(release_date__month=current_month)
    coming_next_month = Movie.objects.filter(release_date__month=(current_month+1 if current_month < 12 else 1))
    
    # Use the proper field for Oscar contenders
    oscar_contenders = Movie.objects.filter(is_oscar_contender=True)
    
    # Get watchlist movies for current user
    watchlist_movies = []
    if request.user.is_authenticated:
        watchlist_movies = [item.movie.id for item in WatchlistItem.objects.filter(user=request.user)]
    
    context = {
        'coming_this_month': coming_this_month,
        'coming_next_month': coming_next_month,
        'oscar_contenders': oscar_contenders,
        'watchlist_movies': watchlist_movies,
    }
    return render(request, 'home3.html', context)


@login_required
def watchlist(request):
    watchlist_items = WatchlistItem.objects.filter(user=request.user).order_by('-added_at')
    return render(request, 'watchlist.html', {'watchlist_items': watchlist_items})


@login_required
def add_to_watchlist(request):
    if request.method == 'POST' and request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        movie_id = request.POST.get('movie_id')
        movie = get_object_or_404(Movie, id=movie_id)
        
        # Add to watchlist if not already there
        watchlist_item, created = WatchlistItem.objects.get_or_create(
            user=request.user,
            movie=movie
        )
        
        if created:
            return JsonResponse({'status': 'added', 'message': f'{movie.title} added to watchlist'})
        else:
            return JsonResponse({'status': 'exists', 'message': f'{movie.title} is already in your watchlist'})
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)


@login_required
def remove_from_watchlist(request):
    if request.method == 'POST' and request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        movie_id = request.POST.get('movie_id')
        
        # Find and remove the item
        try:
            watchlist_item = WatchlistItem.objects.get(user=request.user, movie_id=movie_id)
            movie_title = watchlist_item.movie.title
            watchlist_item.delete()
            return JsonResponse({'status': 'removed', 'message': f'{movie_title} removed from watchlist'}),

        except WatchlistItem.DoesNotExist:  
            return JsonResponse({'status': 'error', 'message': 'Movie not in watchlist'})
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)

 # Template with the form


 # fallback in case method is not POST


# Load OpenAI API key
api_key = os.getenv("OPENAI_API_KEY") or settings.OPENAI_API_KEY
client = OpenAI(api_key=api_key)


@csrf_exempt
def chatbot_api(request):
    """
    Handle API requests for chatbot responses using OpenAI
    """
    print("📩 API received a request!")  # Debugging
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            user_input = data.get("message", "").strip()
            if not user_input:
                return JsonResponse({"error": "Message cannot be empty"}, status=400)
            
            print("🔑 OpenAI API Key Loaded:", api_key[:8] + "..." if api_key else "Not found")

            # OpenAI API Call
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": user_input}]
            )
            chatbot_reply = response.choices[0].message.content
            return JsonResponse({"response": chatbot_reply})

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)
        except Exception as e:
            print(f"❌ Error: {str(e)}")
            return JsonResponse({"error": f"Something went wrong: {str(e)}"}, status=500)
    
    return JsonResponse({"error": "Only POST requests are accepted"}, status=405)


def chatbot_page(request):
    """
    Render the chatbot interface (base.html)
    """
    return render(request, "home.html")


# Basic view functions for your pages
def home_view(request):
    return render(request, 'home.html')


def about(request):
    return render(request, 'user.html')




def contact(request):
    if request.method == 'POST':
        form = ContactForm(request.POST)
        if form.is_valid():
            form.save()
            return render(request, 'contact.html', {'form': ContactForm(), 'success': True})
    else:
        form = ContactForm()
    
    return render(request, 'contact.html', {'form': form})



def rate_movie_page(request):
    return render(request, 'recomend.html')


def card2(request):
    return render(request, 'card2.html')


def card1(request):
    return render(request, 'card1.html')

def dashboard(request):
    return render(request, 'dashboard.html')
def n(request):
    return render(request, 'n.html')
def people(request):
    return render(request, 'people.html')
def recomend(request):
    return render(request, 'recomend.html')



def jatt_juliet_reviews(request):
    reviews = JattJulietReview.objects.all()
    
    if request.method == 'POST':
        name = request.POST.get('name')
        review_content = request.POST.get('review')
        
        if name and review_content:  # Ensure data is present
            # Create a new review
            review = JattJulietReview(name=name, content=review_content)
            review.save()
            print(f"Review saved: {name} - {review_content[:20]}...")  # Debug print
            
            messages.success(request, 'Your review has been submitted successfully!')
            return redirect('jatt_juliet_reviews')
        else:
            messages.error(request, 'Name and review content are required.')
    
    return render(request, 'card1.html', {
        'reviews': reviews
    })


# quiz/views.py


from django.views.decorators.csrf import ensure_csrf_cookie
from django.contrib.sessions.models import Session
import json
import random

from .models import Question, QuizAttempt, UserAnswer

@ensure_csrf_cookie
def quiz_home(request):
    """Render the main quiz page and ensure the CSRF token is set"""
    return render(request, 'quiz.html')

def get_questions(request):
    """API endpoint to get quiz questions"""
    # Get all questions
    questions = list(Question.objects.all())
    
    # Select 5 random questions if there are more than 5
    if len(questions) > 5:
        questions = random.sample(questions, 5)
    
    # Create a new quiz attempt
    quiz_attempt = create_quiz_attempt(request, len(questions))
    
    # Store quiz_attempt_id in session
    request.session['quiz_attempt_id'] = quiz_attempt.id
    
    # Format questions for JSON response
    questions_data = []
    for question in questions:
        options = question.get_options()
        random.shuffle(options)  # Randomize options order
        
        questions_data.append({
            'id': question.id,
            'question': question.question_text,
            'options': options,
            'correct_answer': question.correct_answer
        })
    
    return JsonResponse(questions_data, safe=False)

def create_quiz_attempt(request, total_questions):
    """Create a new quiz attempt for the current user/session"""
    if request.user.is_authenticated:
        return QuizAttempt.objects.create(
            user=request.user,
            total_questions=total_questions
        )
    else:
        # For anonymous users, use session key
        if not request.session.exists(request.session.session_key):
            request.session.create()
        
        return QuizAttempt.objects.create(
            session_key=request.session.session_key,
            total_questions=total_questions
        )

def submit_answer(request):
    """API endpoint to submit an answer for a question"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST requests allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        question_id = data.get('question_id')
        selected_answer = data.get('selected_answer')
        response_time = data.get('response_time', 30)  # Default to max time if not provided
        
        # Get the quiz attempt from session
        quiz_attempt_id = request.session.get('quiz_attempt_id')
        
        if not quiz_attempt_id:
            return JsonResponse({'error': 'No active quiz session'}, status=400)
        
        quiz_attempt = QuizAttempt.objects.get(id=quiz_attempt_id)
        question = Question.objects.get(id=question_id)
        
        # Check if answer is correct
        is_correct = selected_answer == question.correct_answer
        
        # Save user's answer
        UserAnswer.objects.create(
            quiz_attempt=quiz_attempt,
            question=question,
            selected_answer=selected_answer,
            is_correct=is_correct,
            response_time=response_time
        )
        
        # Update quiz score if answer is correct
        if is_correct:
            quiz_attempt.score += 1
            quiz_attempt.save()
        
        return JsonResponse({
            'success': True,
            'is_correct': is_correct
        })
    
    except (KeyError, ValueError, Question.DoesNotExist, QuizAttempt.DoesNotExist) as e:
        return JsonResponse({'error': str(e)}, status=400)

def submit_score(request):
    """API endpoint to submit the final score after quiz completion"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST requests allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        score = data.get('score')
        total = data.get('total')
        
        # Get the quiz attempt from session
        quiz_attempt_id = request.session.get('quiz_attempt_id')
        
        if not quiz_attempt_id:
            return JsonResponse({'error': 'No active quiz session'}, status=400)
        
        quiz_attempt = QuizAttempt.objects.get(id=quiz_attempt_id)
        
        # Update final score and total (in case they differ)
        quiz_attempt.score = score
        quiz_attempt.total_questions = total
        quiz_attempt.save()
        
        # Clear quiz session
        if 'quiz_attempt_id' in request.session:
            del request.session['quiz_attempt_id']
        
        return JsonResponse({
            'success': True,
            'message': 'Score saved successfully',
            'score': score,
            'total': total
        })
    
    except (KeyError, ValueError, QuizAttempt.DoesNotExist) as e:
        return JsonResponse({'error': str(e)}, status=400)
FLASK_API_BASE_URL = "http://127.0.0.1:5000/api"
REVIEWS_ENDPOINT = f"{FLASK_API_BASE_URL}/reviews"

def is_admin(user):
    return user.is_authenticated and user.is_staff

# Review views
def reviews_list(request):
    """Display all submitted reviews"""
    try:
        # Add timeout to prevent hanging if Flask server is down
        response = requests.get(f"{REVIEWS_ENDPOINT}", timeout=5)
        
        if response.status_code == 200:
            reviews = response.json()
            print(f"Successfully retrieved {len(reviews)} reviews")  # Debug print
            return render(request, "reviews_list.html", {"reviews": reviews})
        else:
            error_message = f"API returned status code: {response.status_code}"
            print(f"API error: {error_message}")  # Debug print
            messages.error(request, f"Failed to load reviews: {error_message}")
            return render(request, "reviews_list.html", {"reviews": [], "api_error": error_message})
    
    except Exception as e:
        print(f"Exception in reviews_list view: {str(e)}")  # Debug print
        messages.error(request, f"An unexpected error occurred: {str(e)}")
        return render(request, "reviews_list.html", {"reviews": [], "api_error": str(e)})

def review_detail(request, review_id):
    """Display a single review's details"""
    try:
        response = requests.get(f"{REVIEWS_ENDPOINT}/{review_id}", timeout=5)
        
        if response.status_code == 200:
            review = response.json()
            return render(request, "review_detail.html", {"review": review})
        elif response.status_code == 404:
            messages.error(request, "Review not found in the API")
            return redirect("reviews_list")
        else:
            messages.error(request, f"API error (status code: {response.status_code})")
            return redirect("reviews_list")
    
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        messages.error(request, f"Could not connect to the API server: {str(e)}")
        return redirect("reviews_list")
    
    except Exception as e:
        messages.error(request, f"An unexpected error occurred: {str(e)}")
        return redirect("reviews_list")

@login_required
def submit_review(request):
    """Handle review form submissions"""
    if request.method == "POST":
        data = {
            "movie_name": request.POST.get("movie_name"),
            "review": request.POST.get("review"),
            "rating": request.POST.get("rating")
        }
        
        # Validate required fields
        if not all(data.values()):
            messages.error(request, "All fields are required")
            return render(request, "submit_review.html", {"form_data": data})
        
        # Add headers for authentication
        # The Flask API expects Flask-Login authentication, but we need to send the API key
        # in a real-world scenario, you would implement proper auth between services
        
        response = requests.post(f"{REVIEWS_ENDPOINT}", json=data)
        
        if response.status_code == 201:
            messages.success(request, "Your review has been submitted successfully!")
            return redirect("reviews_list")
        else:
            error_msg = response.json().get("error", "Failed to submit review") if response.content else "Failed to submit review"
            messages.error(request, error_msg)
            return render(request, "submit_review.html", {"form_data": data})
    
    return render(request, "submit_review.html")

@login_required
def edit_review(request, review_id):
    """Edit an existing review"""
    # First, fetch the existing review
    try:
        response = requests.get(f"{REVIEWS_ENDPOINT}/{review_id}", timeout=5)
        if response.status_code != 200:
            messages.error(request, "Could not find the review to edit")
            return redirect("reviews_list")
        
        existing_review = response.json()
        
        # Check if user is authorized to edit this review
        # In a real app, you would verify ownership or admin status
        
        if request.method == 'POST':
            updated_data = {
                "movie_name": request.POST.get("movie_name"),
                "review": request.POST.get("review"),
                "rating": request.POST.get("rating")
            }
            
            # Validate required fields
            if not all(updated_data.values()):
                messages.error(request, "All fields are required")
                return render(request, "edit_review.html", {"review": existing_review})
            
            put_response = requests.put(f"{REVIEWS_ENDPOINT}/{review_id}", json=updated_data)
            
            if put_response.status_code == 200:
                messages.success(request, "Review updated successfully!")
                return redirect("reviews_list")
            else:
                error_msg = put_response.json().get("error", "Failed to update review") if put_response.content else "Failed to update review"
                messages.error(request, error_msg)
                return render(request, "edit_review.html", {"review": existing_review})
        
        return render(request, "edit_review.html", {"review": existing_review})
    
    except Exception as e:
        messages.error(request, f"An error occurred: {str(e)}")
        return redirect("reviews_list")

@login_required
def delete_review(request, review_id):
    """Delete a review"""
    if request.method == "POST":
        try:
            response = requests.delete(f"{REVIEWS_ENDPOINT}/{review_id}", timeout=5)
            if response.status_code == 200:
                messages.success(request, "Review deleted successfully.")
            elif response.status_code == 404:
                messages.error(request, "Review not found.")
            else:
                messages.error(request, f"Failed to delete review (Status code: {response.status_code}).")
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            messages.error(request, f"API connection error: {str(e)}")
        except Exception as e:
            messages.error(request, f"An unexpected error occurred: {str(e)}")
    
    return redirect("reviews_list")