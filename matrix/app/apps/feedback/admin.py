from django.contrib import admin
from .models import Feedback


@admin.register(Feedback)
class FeedbackAdmin(admin.ModelAdmin):
    list_display = ('subject', 'type', 'status', 'author', 'created_at', 'answered_at')
    list_filter = ('type', 'status', 'created_at')
    search_fields = ('subject', 'description', 'answer', 'author__username')
    readonly_fields = ('id', 'created_at', 'updated_at')