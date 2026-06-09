"""
Management command to create RBAC groups and optionally assign users.

Location: apps/accounts/management/commands/setup_groups.py
  (or any app in INSTALLED_APPS that has the management/commands/ folder)

Usage:
  # Create groups only
  sudo docker compose exec app python manage.py setup_groups

  # Create groups and assign a user to a role
  sudo docker compose exec app python manage.py setup_groups --usuario admin --perfil Administrador
  sudo docker compose exec app python manage.py setup_groups --usuario joao --perfil Operador
  sudo docker compose exec app python manage.py setup_groups --usuario maria --perfil Visualizador

  # List users and their current roles
  sudo docker compose exec app python manage.py setup_groups --listar
"""
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group

GRUPOS = ['Administrador', 'Operador', 'Visualizador']

User = get_user_model()


class Command(BaseCommand):
    help = 'Creates RBAC groups and allows assigning users to them'

    def add_arguments(self, parser):
        parser.add_argument('--usuario', type=str, help='Username to assign to a role')
        parser.add_argument('--perfil', type=str, choices=GRUPOS, help='Role to assign')
        parser.add_argument('--listar', action='store_true', help='List users and their current roles')

    def handle(self, *args, **options):
        # Create groups if they do not exist
        for nome in GRUPOS:
            grupo, created = Group.objects.get_or_create(name=nome)
            if created:
                self.stdout.write(self.style.SUCCESS(f'  ✓ Grupo criado: {nome}'))
            else:
                self.stdout.write(f'  · Grupo já existe: {nome}')

        # List users and their roles
        if options['listar']:
            self.stdout.write('\n── Users and roles ──')
            for u in User.objects.all().order_by('username'):
                grupos = ', '.join(u.groups.values_list('name', flat=True)) or '(no group)'
                superuser = ' [SUPERUSER]' if u.is_superuser else ''
                self.stdout.write(f'  {u.username:<20} {grupos}{superuser}')
            return

        # Assign user to a role
        if options['usuario'] and options['perfil']:
            try:
                user = User.objects.get(username=options['usuario'])
            except User.DoesNotExist:
                self.stdout.write(self.style.ERROR(f'User "{options["usuario"]}" not found.'))
                return

            # Remove from other role groups before adding
            user.groups.remove(*Group.objects.filter(name__in=GRUPOS))
            grupo = Group.objects.get(name=options['perfil'])
            user.groups.add(grupo)
            self.stdout.write(self.style.SUCCESS(
                f'  ✓ {user.username} atribuído ao perfil {options["perfil"]}'
            ))

        elif options['usuario'] or options['perfil']:
            self.stdout.write(self.style.WARNING(
                'Provide both --usuario AND --perfil to assign a role.'
            ))