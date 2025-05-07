from django import forms
from .models import ContactMessage
from .models import Newsletter
class ContactForm(forms.ModelForm):
    class Meta:
        model = ContactMessage
        fields = ['name', 'email', 'phone', 'subject', 'message']
        widgets = {
            'name': forms.TextInput(attrs={'placeholder': 'John Doe', 'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'placeholder': 'john@example.com', 'class': 'form-control'}),
            'phone': forms.TextInput(attrs={'placeholder': '+1 (234) 567-8900', 'class': 'form-control'}),
            'subject': forms.Select(attrs={'class': 'form-control'}),
            'message': forms.Textarea(attrs={'placeholder': 'How can we help you?', 'class': 'form-control', 'rows': 5}),
        }
# forms.py





class NewsletterForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'placeholder': 'Your email address',
            'class': 'form-control',
            'aria-label': 'Email address for newsletter'
        })
    )        



from .models import MovieRating

class MovieRatingForm(forms.ModelForm):
    rate = forms.IntegerField(
        min_value=1, 
        max_value=5, 
        widget=forms.HiddenInput()
    )
    
    class Meta:
        model = MovieRating
        fields = ['rate']
