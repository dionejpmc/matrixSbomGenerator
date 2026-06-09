
"""
apps/hunting/urls.py

Include in the main urls.py:
    path('hunting/', include('apps.hunting.urls')),
"""
from django.urls import path
from . import views
 
urlpatterns = [
    # Main page
    path('', views.hunting_view, name='hunting'),
 
    # APIs
    path('api/overview/',   views.api_overview,          name='hunting_api_overview'),
    path('api/component/',  views.api_search_component,  name='hunting_api_component'),
    path('api/cve/',        views.api_search_cve,        name='hunting_api_cve'),
    path('api/purl/',       views.api_search_purl,       name='hunting_api_purl'),
]
 