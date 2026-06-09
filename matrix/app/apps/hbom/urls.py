from django.urls import path
from . import views

app_name = 'hbom'

urlpatterns = [
    # HBOM
    path('sbom/<uuid:sbom_id>/', views.api_hbom_get_or_create, name='get_or_create'),
    path('<uuid:hbom_id>/components/', views.api_hbom_add_component, name='add_component'),
    path('components/<uuid:component_id>/', views.api_hbom_delete_component, name='delete_component'),
    path('components/<uuid:component_id>/update/', views.api_hbom_update_component, name='update_component'),

    # EMB3D — reads from the static JSON dataset
    path('emb3d/properties/', views.api_emb3d_properties, name='emb3d_properties'),
    path('emb3d/threats/', views.api_emb3d_threats_for_pids, name='emb3d_threats'),

    # Threats and Mitigations
    path('components/<uuid:component_id>/threats/', views.api_component_add_threats, name='add_threats'),
    path('threats/<uuid:threat_id>/', views.api_component_remove_threat, name='remove_threat'),
    path('mitigations/<uuid:mitigation_id>/', views.api_mitigation_update_status, name='update_mitigation'),
    path('emb3d/mitigations/<str:mitigation_id>/', views.api_emb3d_mitigation_detail, name='emb3d_mitigation_detail'),
]