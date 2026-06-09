"""
core/mongo.py

Centralised MongoDB client for logging.

Collections:
  - task_logs   → Celery task logs (re-scan, Grype update, upload)
  - audit_logs  → user action audit trail
  - error_logs  → Django application errors

Usage:
    from core.mongo import log_task, log_audit, log_error

    log_task('run_grype_scan', 'SUCCESS', upload_id='abc', product='Test', duration=16.5)
    log_audit(request.user, 'DEACTIVATE_PRODUCT', product_id=42, product_name='Test')
    log_error('api_components', str(e), traceback=tb)
"""
import os
import logging
from datetime import datetime, timezone
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

logger = logging.getLogger(__name__)

_client = None
_db = None


def get_db():
    """Returns the MongoDB connection (singleton)."""
    global _client, _db
    if _db is None:
        uri = os.getenv('MONGODB_URI', 'mongodb://mongo:27017/')
        db_name = os.getenv('MONGODB_DB', 'matrix_logs')
        try:
            _client = MongoClient(uri, serverSelectionTimeoutMS=3000)
            _client.admin.command('ping')  # Test connection
            _db = _client[db_name]
            logger.info(f"[MongoDB] Connected to {uri}/{db_name}")
        except ConnectionFailure as e:
            logger.error(f"[MongoDB] Connection failed: {e}")
            _db = None
    return _db


def _now():
    return datetime.now(timezone.utc)


# ─────────────────────────────────────────────────────────────
# TASK LOGS — Celery tasks
# ─────────────────────────────────────────────────────────────

def log_task(task_name, status, **kwargs):
    """
    Records the execution of a Celery task.

    Args:
        task_name: task name (e.g. 'update_grype_db')
        status: 'STARTED' | 'SUCCESS' | 'FAILURE'
        **kwargs: extra data (upload_id, product, duration, error, changes, etc.)

    Example:
        log_task('run_grype_scan', 'SUCCESS',
                 upload_id='abc123',
                 product='Product v1.0',
                 duration_seconds=16.5,
                 new_vulns=3,
                 updated_vulns=242)
    """
    db = get_db()
    if db is None:
        return

    doc = {
        'timestamp': _now(),
        'task': task_name,
        'status': status,
        **kwargs,
    }
    try:
        db.task_logs.insert_one(doc)
    except Exception as e:
        logger.error(f"[MongoDB] Failed to save task log: {e}")


# ─────────────────────────────────────────────────────────────
# AUDIT LOGS — user actions
# ─────────────────────────────────────────────────────────────

def log_audit(user, action, **kwargs):
    """
    Records a user action in the audit log.

    Args:
        user: Django User object (or username string)
        action: descriptive string (e.g. 'DEACTIVATE_PRODUCT', 'UPLOAD_SBOM')
        **kwargs: extra data (product_id, product_name, ip, etc.)

    Examples:
        log_audit(request.user, 'UPLOAD_SBOM',
                  product_name='Product',
                  product_version='1.0',
                  ip=request.META.get('REMOTE_ADDR'))

        log_audit(request.user, 'DEACTIVATE_PRODUCT',
                  product_id=42,
                  product_name='PLC 5001')

        log_audit(request.user, 'LOGIN')
        log_audit(request.user, 'CHANGE_MITIGATION_STATUS',
                  cve_id='CVE-2021-44228',
                  old_status='PENDING',
                  new_status='ACCEPTED')
    """
    db = get_db()
    if db is None:
        return

    username = user.username if hasattr(user, 'username') else str(user)
    groups = list(user.groups.values_list('name', flat=True)) if hasattr(user, 'groups') else []

    doc = {
        'timestamp': _now(),
        'user': username,
        'groups': groups,
        'action': action,
        **kwargs,
    }
    try:
        db.audit_logs.insert_one(doc)
    except Exception as e:
        logger.error(f"[MongoDB] Failed to save audit log: {e}")


# ─────────────────────────────────────────────────────────────
# ERROR LOGS — application errors
# ─────────────────────────────────────────────────────────────

def log_error(context, error_message, **kwargs):
    """
    Records an application error.

    Args:
        context: where the error occurred (e.g. 'api_components', 'process_sbom_task')
        error_message: error message string
        **kwargs: extra data (traceback, user, upload_id, etc.)

    Example:
        import traceback
        try:
            ...
        except Exception as e:
            log_error('api_components', str(e), traceback=traceback.format_exc())
    """
    db = get_db()
    if db is None:
        return

    doc = {
        'timestamp': _now(),
        'context': context,
        'error': error_message,
        **kwargs,
    }
    try:
        db.error_logs.insert_one(doc)
    except Exception as e:
        logger.error(f"[MongoDB] Failed to save error log: {e}")