import uuid
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Feedback',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('type', models.CharField(choices=[('question', 'Dúvida'), ('improvement', 'Melhoria'), ('problem', 'Problema')], default='question', max_length=20)),
                ('subject', models.CharField(max_length=200)),
                ('description', models.TextField()),
                ('status', models.CharField(choices=[('open', 'Aberto'), ('answered', 'Respondido'), ('analyzing', 'Em análise'), ('planned', 'Planejado'), ('backlog', 'Backlog'), ('implemented', 'Implementado'), ('rejected', 'Rejeitado'), ('duplicate', 'Duplicado')], default='open', max_length=20)),
                ('answer', models.TextField(blank=True, default='')),
                ('answered_at', models.DateTimeField(blank=True, null=True)),
                ('seen_by_author', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('answered_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='feedbacks_answered', to=settings.AUTH_USER_MODEL)),
                ('author', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='feedbacks', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.AddIndex(
            model_name='feedback',
            index=models.Index(fields=['author', 'status'], name='feedback_fe_author__idx'),
        ),
        migrations.AddIndex(
            model_name='feedback',
            index=models.Index(fields=['status'], name='feedback_fe_status_idx'),
        ),
    ]