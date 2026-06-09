"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from apps.accounts.password_views import force_password_change_view

from django.contrib import admin
from django.urls import path, include
from django.conf.urls.i18n import i18n_patterns
from django.contrib.auth import views as auth_views
from usuarios import views as usuarios_views
from apps.sbom.views import upload_sbom_view
from apps.sbom.csv_views import approval_view
from apps.accounts.users import SignUpView
from apps.accounts.user_management import api_user_create
from apps.accounts.user_management import (
    user_management_view, api_user_list, api_user_edit,
    api_user_deactivate, api_user_activate, api_bu_list,
)
from apps.organizations.views import api_bu_list_create, api_bu_delete

urlpatterns = [
    path('i18n/', include('django.conf.urls.i18n')),
    path('admin/', admin.site.urls),
    path('accounts/login/', auth_views.LoginView.as_view(template_name='accounts/login.html'), name='login'),
    path('', usuarios_views.dashboard, name='dashboard'),
    path('upload/', upload_sbom_view, name='upload_sbom'),
    path('signup/', SignUpView.as_view(), name='signup'),
    path('logoff/', auth_views.LogoutView.as_view(), name='logoff'),
    path('sbom/', include('apps.sbom.urls')),
    path('hbom/', include('apps.hbom.urls')),
    path('hunting/', include('apps.hunting.urls')),
    path('rootfs/', include('apps.rootfs.urls')),
    path('archive/', include('apps.archive.urls')),
    path('sbom/aprovacao/', approval_view, name='approval'),
    path('organizations/api/bus/', api_bu_list_create, name='api_bu_list_create'),
    path('organizations/api/bus/<int:bu_id>/', api_bu_delete, name='api_bu_delete'),
    # User management
    path('accounts/usuarios/', user_management_view, name='user_management'),
    path('accounts/api/users/', api_user_list, name='api_user_list'),
    path('accounts/api/users/<int:user_id>/edit/', api_user_edit, name='api_user_edit'),
    path('accounts/api/users/<int:user_id>/deactivate/', api_user_deactivate, name='api_user_deactivate'),
    path('accounts/api/users/<int:user_id>/activate/', api_user_activate, name='api_user_activate'),
    path('accounts/api/bus/', api_bu_list, name='api_bu_list'),
    path('oidc/', include('mozilla_django_oidc.urls')),
   
    path('accounts/api/users/create/', api_user_create, name='api_user_create'),
    path('accounts/change-password/', force_password_change_view, name='force_password_change'),
]