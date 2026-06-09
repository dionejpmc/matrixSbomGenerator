#!/bin/bash
# Função para aguardar o PostgreSQL
echo "Aguardando PostgreSQL em matrix-db:5432..."
until pg_isready -h db -U ${POSTGRES_USER} -d ${POSTGRES_DB}; do
  sleep 1
done
# Função para aguardar o Neo4j (Porta Bolt 7687)
echo "Aguardando Neo4j em matrix-graph:7687..."
until timeout 1s bash -c '< /dev/tcp/neo4j/7687' 2>/dev/null; do
  sleep 1
done
echo "Bancos de dados prontos! Iniciando migrações..."
# Executa migrações do Django
python manage.py migrate --noinput
python manage.py collectstatic --noinput
python manage.py setup_groups
# Cria superuser admin/admin se não existir e força troca de senha
python manage.py shell -c "
from django.contrib.auth import get_user_model
from apps.accounts.models import UserProfile
User = get_user_model()
if not User.objects.filter(username='admin').exists():
    user = User.objects.create_superuser('admin', 'admin@matrix.local', 'admin')
    profile, _ = UserProfile.objects.get_or_create(user=user)
    profile.must_change_password = True
    profile.save()
    print('Superuser admin criado — troca de senha obrigatória no primeiro login')
else:
    print('Superuser admin já existe — sem alterações')
"
# Inicia o servidor (ou o worker, dependendo do comando no compose)
exec "$@"