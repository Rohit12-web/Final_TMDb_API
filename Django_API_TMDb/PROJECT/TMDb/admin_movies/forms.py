# admin_movies/forms.py
from django import forms
from app1.models import Movie
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError

class MovieForm(forms.ModelForm):
    class Meta:
        model = Movie
        fields = ['title', 'description', 'release_date', 'image_url', 'is_oscar_contender','is_coming_this_month','is_coming_next_month',]
        widgets = {
            'release_date': forms.DateInput(attrs={'type': 'date'}),
            'description': forms.Textarea(attrs={'rows': 4}),
        }
    
    def clean_image_url(self):
        image_url = self.cleaned_data.get('image_url')
        if image_url:
            validator = URLValidator()
            try:
                validator(image_url)
            except ValidationError:
                raise forms.ValidationError("Please enter a valid URL for the movie poster.")
        return image_url