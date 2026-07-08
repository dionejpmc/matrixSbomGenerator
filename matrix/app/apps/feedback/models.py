"""
apps/feedback/models.py — Canal de feedback dos usuários.

Feedback assíncrono e leve: o usuário envia uma dúvida, sugestão de melhoria
ou reporta um problema; o admin lê, classifica com um status e (opcionalmente)
responde em texto. Uma resposta por feedback — NÃO é chat, NÃO é sistema de
incidentes/IR. O tipo "Problema" é apenas a natureza do feedback, não dispara
nenhum fluxo de tratamento de incidente.
"""

import uuid
from django.db import models
from django.conf import settings


class Feedback(models.Model):

    class Type(models.TextChoices):
        QUESTION    = 'question',    'Dúvida'
        IMPROVEMENT = 'improvement', 'Melhoria'
        PROBLEM     = 'problem',     'Problema'

    class Status(models.TextChoices):
        OPEN        = 'open',        'Aberto'
        ANSWERED    = 'answered',    'Respondido'
        ANALYZING   = 'analyzing',   'Em análise'
        PLANNED     = 'planned',     'Planejado'
        BACKLOG     = 'backlog',     'Backlog'
        IMPLEMENTED = 'implemented', 'Implementado'
        REJECTED    = 'rejected',    'Rejeitado'
        DUPLICATE   = 'duplicate',   'Duplicado'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # quem abriu
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name='feedbacks'
    )
    type = models.CharField(max_length=20, choices=Type.choices, default=Type.QUESTION)
    subject = models.CharField(max_length=200)
    description = models.TextField()

    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)

    # resposta do admin (opcional — o status sozinho já pode bastar)
    answer = models.TextField(blank=True, default='')
    answered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='feedbacks_answered'
    )
    answered_at = models.DateTimeField(null=True, blank=True)

    # controle do badge: o autor já viu a resposta/atualização do admin?
    seen_by_author = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['author', 'status']),
            models.Index(fields=['status']),
        ]

    def __str__(self):
        return f'[{self.get_type_display()}] {self.subject} ({self.get_status_display()})'

    @property
    def has_answer(self):
        return bool(self.answer.strip())