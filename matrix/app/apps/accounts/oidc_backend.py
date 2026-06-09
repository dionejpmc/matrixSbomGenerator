"""
apps/accounts/oidc_backend.py

Backend OIDC customizado para o Matrix.

Comportamento:
- Autentica via Keycloak corporativo (OIDC)
- Busca o usuário LOCAL pelo username (preferred_username do token)
- Não cria usuários novos — deve existir previamente no Matrix
- Usa o perfil/grupos locais para RBAC
"""
import logging
from mozilla_django_oidc.auth import OIDCAuthenticationBackend

logger = logging.getLogger(__name__)


class MatrixOIDCBackend(OIDCAuthenticationBackend):
    """
    Autentica via Keycloak mas usa o perfil do usuário local.
    O username do Keycloak (preferred_username) deve corresponder
    ao username cadastrado no Matrix.
    """

    def filter_users_by_claims(self, claims):
        """
        Busca o usuário local pelo preferred_username do token Keycloak.
        Ex: token retorna preferred_username='joao.silva' → busca User(username='joao.silva')
        """
        username = claims.get('preferred_username', '').strip().lower()

        if not username:
            logger.warning('[OIDC] Token sem preferred_username — acesso negado')
            return self.UserModel.objects.none()

        users = self.UserModel.objects.filter(
            username__iexact=username,
            is_active=True,
        )

        if not users.exists():
            logger.warning(f'[OIDC] Usuário "{username}" não encontrado no Matrix — acesso negado')

        return users

    def create_user(self, claims):
        """Bloqueia criação automática de usuários."""
        username = claims.get('preferred_username', '')
        logger.warning(f'[OIDC] Tentativa de criar usuário "{username}" bloqueada — deve ser cadastrado manualmente no Matrix')
        return None

    def update_user(self, user, claims):
        """
        Atualiza nome e email do usuário local com os dados do Keycloak.
        Não altera username, BU nem role — controlados localmente.
        """
        first_name = claims.get('given_name', '').strip()
        last_name  = claims.get('family_name', '').strip()
        email      = claims.get('email', '').strip()

        changed = False
        if first_name and user.first_name != first_name:
            user.first_name = first_name
            changed = True
        if last_name and user.last_name != last_name:
            user.last_name = last_name
            changed = True
        if email and user.email != email:
            user.email = email
            changed = True

        if changed:
            user.save(update_fields=['first_name', 'last_name', 'email'])
            logger.info(f'[OIDC] Dados atualizados para: {user.username}')

        return user

    def verify_claims(self, claims):
        """Verifica se o token tem o mínimo necessário."""
        verified = super().verify_claims(claims)
        if not claims.get('preferred_username'):
            logger.warning('[OIDC] Token sem preferred_username')
            return False
        return verified