"""
apps/archive/urls.py

Incluir no config/urls.py:
    path('archive/', include('apps.archive.urls')),
"""
from django.urls import path
from . import views

urlpatterns = [
    path('', views.archive_view, name='archive'),
    path('api/products/', views.api_archive_products, name='archive_api_products'),
    path('api/products/<int:product_id>/components/', views.api_archive_components, name='archive_api_components'),
    path('api/products/<int:product_id>/export/', views.api_archive_export, name='archive_api_export'),
    path('api/products/<int:product_id>/delete/', views.api_archive_delete, name='archive_api_delete'),
]