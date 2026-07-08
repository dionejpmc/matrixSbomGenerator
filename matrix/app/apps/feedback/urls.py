"""apps/feedback/urls.py — rotas do canal de feedback (prefixo /feedback/)."""

from django.urls import path
from . import views

urlpatterns = [
    # usuário
    path('api/create/',    views.api_create,    name='feedback_create'),
    path('api/mine/',      views.api_mine,      name='feedback_mine'),
    path('api/mark-seen/', views.api_mark_seen, name='feedback_mark_seen'),
    path('api/badge/',     views.api_badge,     name='feedback_badge'),
    # admin
    path('api/all/',                   views.api_all,     name='feedback_all'),
    path('api/<uuid:feedback_id>/respond/', views.api_respond, name='feedback_respond'),
]