"""Atomic database release of an already verified, stored A1 report.

External object storage is not part of the SQL transaction. The caller must
reconcile orphaned objects on failed commits and must verify signer authorization
before invoking this function. This module does not activate clinical release.
"""
from datetime import datetime
from a1_report_link import stage_signed_version


def commit_signed_release(*, model, db_session, exam, artifact, signer_name,
                          finance_entry=None, occurrences=(), now=None):
    """Commit report metadata, clinical release, and finance in one SQL transaction.

    Caller must prepare and validate the signed PDF before invoking this function.
    On any failure, rollback the SQL session; never release an unsigned report.
    """
    if not isinstance(signer_name, str) or not signer_name.strip():
        raise ValueError("Responsável pela assinatura não identificado.")
    if getattr(exam, "status", None) == "Liberado":
        raise ValueError("Exame já liberado; revisão requer fluxo específico.")
    exam_id = getattr(exam, "id", None)
    moment = now or datetime.utcnow()
    try:
        row = stage_signed_version(model=model, db_session=db_session,
                                   exam_id=exam_id, artifact=artifact)
        exam.status = "Liberado"
        exam.released_at = moment
        exam.signed_at = moment
        exam.signed_by = signer_name.strip()
        if finance_entry is not None:
            db_session.add(finance_entry)
        for occurrence in occurrences:
            if occurrence.status == "Aberta":
                occurrence.status = "Resolvida"
                occurrence.resolved_at = moment
        db_session.commit()
        return row
    except Exception:
        db_session.rollback()
        raise
