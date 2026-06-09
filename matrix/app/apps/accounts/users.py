from django.urls import reverse_lazy
from django.views.generic import CreateView
from .forms import MatrixUserCreationForm
from django.contrib.auth.models import Group
from django.contrib.auth.mixins import LoginRequiredMixin
from apps.organizations.models import UserBUMembership
from apps.accounts.permissions import is_administrador
from django.core.exceptions import PermissionDenied


# Mapeamento role do membership → nome do Group Django
ROLE_TO_GROUP = {
    'admin':    'Administrador',
    'operator': 'Operador',
    'viewer':   'Visualizador',
}


class SignUpView(LoginRequiredMixin, CreateView):
    form_class = MatrixUserCreationForm
    success_url = reverse_lazy('login')
    template_name = 'registration/signup.html'

    def dispatch(self, request, *args, **kwargs):
        # Only Administrator can create users
        if not is_administrador(request.user):
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        response = super().form_valid(form)
        user = self.object

        # Pega o role escolhido no form
        role = form.cleaned_data.get('role')
        bu = form.cleaned_data.get('business_unit')

        # Atualiza o membership com a BU e role corretos
        # (o signal já criou com a BU padrão — aqui corrigimos para a BU escolhida)
        UserBUMembership.objects.update_or_create(
            user=user,
            defaults={'business_unit': bu, 'role': role}
        )

        # Atribui o Group Django correspondente
        group_name = ROLE_TO_GROUP.get(role)
        if group_name:
            try:
                group = Group.objects.get(name=group_name)
                user.groups.clear()
                user.groups.add(group)
            except Group.DoesNotExist:
                pass  # Groups not yet created — run setup_group first

        return response