# urls.py in your project folder
from django.urls import path
from app1 import views

urlpatterns = [
    # Main views
    path('home3/', views.home3, name='home3'),
    path('', views.home_view, name='home'),
    path('about/', views.about, name='about'),
    path('dashboard/', views.dashboard, name='dashboard'),
    
    # Fix: Renamed routes to avoid conflicts
    path('contact-us/', views.contact, name='contact'),
    
    path('subscribe/', views.subscribe_newsletter, name='subscribe_newsletter'),
    path('rate-movie/', views.rate_movie, name='rate_movie'),
    path('card1/', views.jatt_juliet_reviews, name='jatt_juliet_reviews'),  # Adjust path based on your URL
                             
    path('people/', views.people, name='people'),
    # Authentication URLs 
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.register_view, name='register'),
    
    # Ratings URLs
    path("ratings/", views.ratings_view, name="ratings"),
    # Add the API endpoint for ratings
    path('reviews/', views.reviews_list, name='reviews_list'),
path('reviews/<int:review_id>/', views.review_detail, name='review_detail'),
path('reviews/submit/', views.submit_review, name='submit_review'),
path('reviews/<int:review_id>/edit/', views.edit_review, name='edit_review'),
path('reviews/<int:review_id>/delete/', views.delete_review, name='delete_review'),
    

    path('contact/', views.contact_form, name='contact_form'),
    path('contact/submit/', views.submit_contact, name='submit_contact'),
    path('contacts/', views.contacts_list, name='contacts_list'),
    path('contacts/<int:contact_id>/', views.contact_detail, name='contact_detail'),
    path('contacts/<int:contact_id>/delete/', views.delete_contact, name='delete_contact'),
    # Watchlist URLs
    path('watchlist/', views.view_watchlist, name='watchlist'),
    path('watchlist/toggle/<int:movie_id>/', views.toggle_watchlist, name='toggle_watchlist'),
    
    # Movie pages
    path('card1/', views.card1, name='card1'),
    path('card2/', views.card2, name='card2'),
    path('recomend/', views.recomend, name='recomend'),
    
    # Chatbot
    path('chatbot/', views.chatbot_page, name='chatbot'),
    path('chatbot/api/', views.chatbot_api, name='chatbot_api'),
   
    # Admin movie management
    path('admin/movies/', views.admin_movie_list, name='admin_movie_list'),
    path('admin/movies/add/', views.add_movie, name='add_movie'),
    path('admin/movies/edit/<int:movie_id>/', views.edit_movie, name='edit_movie'),
    path('admin/movies/delete/<int:movie_id>/', views.delete_movie, name='delete_movie'),
    path('quiz/', views.quiz_home, name='quiz_home'),
    path('api/quiz/questions/', views.get_questions, name='get_questions'),
    path('api/quiz/submit/', views.submit_answer, name='submit_answer'),
    path('api/quiz/score/', views.submit_score, name='submit_score'),
]