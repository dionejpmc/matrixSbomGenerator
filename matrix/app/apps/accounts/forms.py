from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from apps.organizations.models import BusinessUnit, UserBUMembership

class MatrixUserCreationForm(UserCreationForm):
    # Adicionamos os campos que NÃO existem no modelo User, mas que precisamos para o RBAC
    business_unit = forms.ModelChoiceField(
        queryset=BusinessUnit.objects.all(),
        label="Unidade de Negócio (BU)",
        empty_label="Selecione a Unidade"
    )
    role = forms.ChoiceField(
        choices=UserBUMembership.ROLE_CHOICES, # Assume que você definiu ROLE_CHOICES no modelo
        label="Nível de Acesso (RBAC)"
    )

    class Meta(UserCreationForm.Meta):
        model = User
        fields = UserCreationForm.Meta.fields + ('first_name', 'last_name', 'email', 'business_unit', 'role')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Aplicando seu estilo Slate/Dark que combinamos antes
        style = 'w-full px-4 py-3 bg-slate-800 border border-slate-700 rounded-lg text-white outline-none mb-4'
        for field in self.fields.values():
            field.widget.attrs.update({'class': style})