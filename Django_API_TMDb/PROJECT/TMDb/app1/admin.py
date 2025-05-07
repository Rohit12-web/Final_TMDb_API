from django.contrib import admin

from .models import ContactMessage, Newsletter, JattJulietReview

@admin.register(ContactMessage)
class ContactMessageAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'subject', 'created_at')
    search_fields = ('name', 'email', 'subject')


@admin.register(Newsletter)
class NewsletterAdmin(admin.ModelAdmin):
    list_display = ('email', 'subscribed_at')
    search_fields = ('email',)
    list_filter = ('subscribed_at',)
    readonly_fields = ('subscribed_at',)
    ordering = ('-subscribed_at',)

    def has_change_permission(self, request, obj=None):
        # Prevent editing of existing newsletter subscriptions
        return False
    


@admin.register(JattJulietReview)
class JattJulietReviewAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_at','content')
    search_fields = ('name', 'content')
    list_filter = ('created_at',)

 # quiz/admin.py
from django.contrib import admin
from .models import Question, QuizAttempt, UserAnswer

class QuestionAdmin(admin.ModelAdmin):
    list_display = ('question_text', 'correct_answer')
    search_fields = ('question_text',)

class UserAnswerInline(admin.TabularInline):
    model = UserAnswer
    extra = 0
    readonly_fields = ('question', 'selected_answer', 'is_correct', 'response_time')
    can_delete = False

class QuizAttemptAdmin(admin.ModelAdmin):
    list_display = ('user', 'session_key', 'score', 'total_questions', 'completion_time')
    inlines = [UserAnswerInline]
    readonly_fields = ('user', 'session_key', 'score', 'total_questions', 'completion_time')

admin.site.register(Question, QuestionAdmin)
admin.site.register(QuizAttempt, QuizAttemptAdmin)   