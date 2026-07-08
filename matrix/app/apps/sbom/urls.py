from django.urls import path
from apps.sbom.views import api_product_graph, api_components
from .views import upload_sbom_view
from .views import *
from .views import api_vex_get, api_vex_declare, api_vex_export
from .csv_views import (
    download_csv_template, api_parse_csv, api_save_manual_sbom,
    approval_view, api_approval_list, api_approve_sbom, api_reject_sbom,
)
from . import views, scan_source

app_name = 'sbom'

urlpatterns = [
    path('upload/', upload_sbom_view, name='upload'),
    path('api/graph/<int:product_id>/', api_product_graph, name='product_graph_api'),
    path('api/components/<int:product_id>/', api_components, name='components_api'),
    path('api/cve/<str:cve_id>/', api_cve_detail, name='cve_detail'),
    path('api/bu-stats/', api_bu_stats, name='bu_stats'),
    path('api/vulns/no-vex/', api_vulns_no_vex, name='vulns_no_vex'),
    path('api/vulns/critical-exploit/', api_vulns_critical_exploit, name='vulns_critical_exploit'),
    path('api/component-products/', api_component_products, name='component_products'),
    path('api/download/<int:product_id>/', api_download_cyclonedx, name='download_cyclonedx'),
    path('api/deactivate/<int:product_id>/', api_deactivate_product, name='deactivate_product'),
    path('api/vex/<int:vulnerability_id>/',         api_vex_get,     name='vex_get'),
    path('api/vex/<int:vulnerability_id>/declare/',  api_vex_declare, name='vex_declare'),
    path('api/vex/export/<int:product_id>/',         api_vex_export,  name='vex_export'),
    path('api/scan-status/<int:product_id>/', api_scan_status, name='scan_status'),
    # CSV manual upload
    path('csv/template/',            download_csv_template,  name='csv_template'), ##Codigo morto
    path('api/csv/parse/',           api_parse_csv,          name='csv_parse'), ##Codigo morto
    path('api/csv/save/',            api_save_manual_sbom,   name='csv_save'), ##Codigo morto
  
    # SBOM Diff
    path('api/diff/uploads/<int:product_id>/', api_diff_uploads, name='diff_uploads'),
    path('api/diff/', api_sbom_diff, name='sbom_diff'),
    # SBOM approval
    path('aprovacao/',               approval_view,          name='approval'),
    path('api/approval/',            api_approval_list,      name='approval_list'),
    path('api/approval/<uuid:upload_id>/approve/', api_approve_sbom, name='approval_approve'),
    path('api/approval/<uuid:upload_id>/reject/',  api_reject_sbom,  name='approval_reject'),
     path("api/scan/source/", scan_source.api_scan_source, name="api_scan_source"),
]