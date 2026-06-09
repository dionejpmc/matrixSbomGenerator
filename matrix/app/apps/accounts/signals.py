from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from apps.organizations.models import UserBUMembership, BusinessUnit

@receiver(post_save, sender=User)
def create_user_rbac_profile(sender, instance, created, **kwargs):
    """
    Automatically creates the access infrastructure when a new user is created.
    """
    if created:
        # 1. Cria UserProfile com must_change_password=True para novos usuários não-superuser
        from apps.accounts.models import UserProfile
        UserProfile.objects.get_or_create(
            user=instance,
            defaults={'must_change_password': not instance.is_superuser}
        )

        # 2. Garante que a BU padrão existe
        bu, _ = BusinessUnit.objects.get_or_create(name="Company X S.A.")

        # 3. Define o role baseado no tipo de usuário
        user_role = 'admin' if instance.is_superuser else 'viewer'

        # 4. Cria o membership
        UserBUMembership.objects.create(
            user=instance,
            business_unit=bu,
            role=user_role
        )

        print(f"RBAC: Profile '{user_role}' created for {instance.username} in unit {bu.name}")