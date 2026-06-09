from django import forms
from .models import SbomFile # Supondo que você criou esse model

class SBOMUploadForm(forms.ModelForm):
    class Meta:
        model = SbomFile
        fields = ['file', 'product']