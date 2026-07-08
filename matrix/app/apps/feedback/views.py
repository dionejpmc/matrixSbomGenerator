"""
apps/feedback/views.py — Endpoints JSON do canal de feedback.

Fluxo do usuário:  criar feedback, listar os próprios, marcar respostas como vistas.
Fluxo do admin:    listar todos, responder e/ou classificar (mudar status).

O badge:
  • usuário  → nº de feedbacks próprios com resposta/atualização não vista
               (seen_by_author = False).
  • admin    → nº de feedbacks com status 'open' (aguardando triagem).
"""

import json
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST, require_GET
from django.utils import timezone

from .models import Feedback

try:
    # mesmo padrão de auditoria usado no resto do projeto
    from core.mongo import log_audit
except Exception:  # auditoria é best-effort; nunca deve quebrar o fluxo
    def log_audit(*args, **kwargs):
        return None


def _is_admin(user):
    """Só o usuário admin responde/classifica. Ajuste conforme o modelo de
    permissão do projeto (aqui: is_superuser OU flag/grupo 'administrador')."""
    if user.is_superuser:
        return True
    # compatibilidade com o esquema de papéis do projeto, se existir
    role = getattr(user, 'role', None)
    if role and str(role).lower() in ('administrador', 'admin'):
        return True
    return user.groups.filter(name__iexact='administrador').exists()


def _serialize(fb, include_author=False):
    data = {
        'id': str(fb.id),
        'type': fb.type,
        'type_display': fb.get_type_display(),
        'subject': fb.subject,
        'description': fb.description,
        'status': fb.status,
        'status_display': fb.get_status_display(),
        'answer': fb.answer,
        'has_answer': fb.has_answer,
        'answered_at': fb.answered_at.isoformat() if fb.answered_at else None,
        'seen_by_author': fb.seen_by_author,
        'created_at': fb.created_at.isoformat(),
    }
    if include_author:
        data['author'] = getattr(fb.author, 'username', str(fb.author_id))
        data['answered_by'] = getattr(fb.answered_by, 'username', None) if fb.answered_by_id else None
    return data


# ── Usuário ──────────────────────────────────────────────────────────────

@login_required
@require_POST
def api_create(request):
    try:
        payload = json.loads(request.body or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'JSON inválido.'}, status=400)

    ftype = (payload.get('type') or '').strip()
    subject = (payload.get('subject') or '').strip()
    description = (payload.get('description') or '').strip()

    if ftype not in Feedback.Type.values:
        return JsonResponse({'error': 'Tipo inválido.'}, status=400)
    if not subject:
        return JsonResponse({'error': 'Informe um assunto.'}, status=400)
    if not description:
        return JsonResponse({'error': 'Descreva sua dúvida, melhoria ou problema.'}, status=400)
    if len(subject) > 200:
        return JsonResponse({'error': 'Assunto muito longo (máx. 200).'}, status=400)

    fb = Feedback.objects.create(
        author=request.user,
        type=ftype,
        subject=subject,
        description=description,
        status=Feedback.Status.OPEN,
        seen_by_author=True,  # o autor acabou de criar; nada novo para ele
    )
    log_audit(request.user, 'FEEDBACK_CREATE', feedback_id=str(fb.id), type=ftype)
    return JsonResponse({'feedback': _serialize(fb)}, status=201)


@login_required
@require_GET
def api_mine(request):
    """Lista os feedbacks do próprio usuário (privado)."""
    qs = Feedback.objects.filter(author=request.user)
    items = [_serialize(fb) for fb in qs]
    unseen = qs.filter(seen_by_author=False).count()
    return JsonResponse({'feedbacks': items, 'unseen': unseen})


@login_required
@require_POST
def api_mark_seen(request):
    """Marca como vistas as respostas/atualizações do próprio usuário (zera o badge)."""
    Feedback.objects.filter(author=request.user, seen_by_author=False).update(seen_by_author=True)
    return JsonResponse({'ok': True})


# ── Admin ────────────────────────────────────────────────────────────────

@login_required
@require_GET
def api_all(request):
    """Lista todos os feedbacks para triagem [somente admin]."""
    if not _is_admin(request.user):
        return JsonResponse({'error': 'Acesso restrito.'}, status=403)

    qs = Feedback.objects.select_related('author', 'answered_by').all()

    status = request.GET.get('status')
    if status and status in Feedback.Status.values:
        qs = qs.filter(status=status)
    ftype = request.GET.get('type')
    if ftype and ftype in Feedback.Type.values:
        qs = qs.filter(type=ftype)

    items = [_serialize(fb, include_author=True) for fb in qs]
    open_count = Feedback.objects.filter(status=Feedback.Status.OPEN).count()
    return JsonResponse({'feedbacks': items, 'open_count': open_count})


@login_required
@require_POST
def api_respond(request, feedback_id):
    """Responde e/ou reclassifica um feedback [somente admin].

    Aceita `answer` (texto opcional) e/ou `status`. Ao menos um deve vir.
    Qualquer atualização do admin marca o feedback como não-visto pelo autor
    (para acender o badge dele).
    """
    if not _is_admin(request.user):
        return JsonResponse({'error': 'Acesso restrito.'}, status=403)

    try:
        fb = Feedback.objects.get(id=feedback_id)
    except Feedback.DoesNotExist:
        return JsonResponse({'error': 'Feedback não encontrado.'}, status=404)

    try:
        payload = json.loads(request.body or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'error': 'JSON inválido.'}, status=400)

    new_status = payload.get('status')
    answer = payload.get('answer')

    changed = False

    if answer is not None:
        answer = answer.strip()
        fb.answer = answer
        fb.answered_by = request.user
        fb.answered_at = timezone.now()
        # se respondeu com texto e o status ainda era 'aberto', vira 'respondido'
        if answer and fb.status == Feedback.Status.OPEN and not new_status:
            fb.status = Feedback.Status.ANSWERED
        changed = True

    if new_status:
        if new_status not in Feedback.Status.values:
            return JsonResponse({'error': 'Status inválido.'}, status=400)
        fb.status = new_status
        changed = True

    if not changed:
        return JsonResponse({'error': 'Nada para atualizar (informe status e/ou resposta).'}, status=400)

    fb.seen_by_author = False  # acende o badge do usuário
    fb.save()

    log_audit(request.user, 'FEEDBACK_RESPOND',
              feedback_id=str(fb.id), status=fb.status, answered=bool(fb.answer))
    return JsonResponse({'feedback': _serialize(fb, include_author=True)})


@login_required
@require_GET
def api_badge(request):
    """Contador do badge, com significado dependente do papel:
       admin → feedbacks 'abertos'; usuário → respostas não vistas."""
    if _is_admin(request.user):
        count = Feedback.objects.filter(status=Feedback.Status.OPEN).count()
        return JsonResponse({'role': 'admin', 'count': count})
    count = Feedback.objects.filter(author=request.user, seen_by_author=False).count()
    return JsonResponse({'role': 'user', 'count': count})