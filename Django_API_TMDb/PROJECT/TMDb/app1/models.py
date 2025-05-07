from django.db import models
from django.contrib.auth.models import User
from django.utils.timezone import now


class Movie(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()
    release_date = models.DateField()
    image_url = models.URLField()
    is_oscar_contender = models.BooleanField(default=False)
    is_coming_this_month=models.BooleanField(default=False)
    is_coming_next_month=models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)
    def __str__(self):
        return self.title

# Using one consistent watchlist model (WatchlistItem)
class WatchlistItem(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='watchlist_items')
    movie = models.ForeignKey(Movie, on_delete=models.CASCADE, related_name='in_watchlists')
    added_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ('user', 'movie')  # Each user can add a movie only once
        
    def __str__(self):
        return f"{self.user.username} - {self.movie.title}"

from django.db import models

class ContactMessage(models.Model):
    SUBJECT_CHOICES = [
        ('general', 'General Inquiry'),
        ('support', 'Technical Support'),
        ('feedback', 'Feedback & Suggestions'),
        ('business', 'Business Collaboration'),
        ('press', 'Press & Media'),
        ('api', 'API Access'),
    ]
    
    name = models.CharField(max_length=100)
    email = models.EmailField()
    phone = models.CharField(max_length=20, blank=True)
    subject = models.CharField(max_length=50, choices=SUBJECT_CHOICES)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - {self.subject}"
    
    # models.py







class Newsletter(models.Model):
    email = models.EmailField(unique=True)
    subscribed_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.email
# I've removed the duplicate Watchlist model since we'll use WatchlistItem consistently



class JattJulietReview(models.Model):
    name = models.CharField(max_length=100)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Review by {self.name}"
    
    class Meta:
        ordering = ['-created_at']



from django.core.validators import MinValueValidator, MaxValueValidator

class MovieRating(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    movie_id = models.IntegerField()  # Store movie ID directly
    rating = models.IntegerField(validators=[MinValueValidator(1), MaxValueValidator(5)])
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ('user', 'movie_id')
    
    def __str__(self):
        return f"{self.user.username}'s {self.rating}-star rating for movie #{self.movie_id}"

# quiz/models.py
from django.db import models
from django.contrib.auth.models import User

class Question(models.Model):
    question_text = models.CharField(max_length=255)
    option_1 = models.CharField(max_length=100)
    option_2 = models.CharField(max_length=100)
    option_3 = models.CharField(max_length=100)
    option_4 = models.CharField(max_length=100)
    correct_answer = models.CharField(max_length=100)
    
    def __str__(self):
        return self.question_text
    
    def get_options(self):
        return [self.option_1, self.option_2, self.option_3, self.option_4]

class QuizAttempt(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    session_key = models.CharField(max_length=40, null=True, blank=True)  # For anonymous users
    score = models.IntegerField(default=0)
    total_questions = models.IntegerField(default=0)
    completion_time = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Attempt by {self.user or 'Anonymous'} - Score: {self.score}/{self.total_questions}"

class UserAnswer(models.Model):
    quiz_attempt = models.ForeignKey(QuizAttempt, on_delete=models.CASCADE, related_name='answers')
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    selected_answer = models.CharField(max_length=100)
    is_correct = models.BooleanField(default=False)
    response_time = models.IntegerField(default=0)  # Time taken to answer in seconds
    
    def __str__(self):
        return f"Answer for {self.question} - Correct: {self.is_correct}"