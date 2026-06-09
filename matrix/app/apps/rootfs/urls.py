from django.urls import path
from .views import upload_rauc_view, upload_ext4_view
from .views import api_check_rauc_hash
from .views import api_deactivate_rootfs_by_product

app_name = 'rootfs'

urlpatterns = [
    path('upload/', upload_rauc_view, name='upload_rauc'),
    path('upload-ext4/', upload_ext4_view, name='upload_ext4'),
    path('api/check-hash/', api_check_rauc_hash, name='check_hash'),
    path('api/deactivate-by-product/<int:product_id>/', api_deactivate_rootfs_by_product, name='deactivate_rootfs_by_product'),
]