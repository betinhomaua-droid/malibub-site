"""Atomic database release of an already verified, stored A1 report.

External object storage is not part of the SQL transaction. The caller must
reconcile orphaned objects on failed commits and must verify signer authorization
before invoking this function. This module does not activate clinical release.
"""
from datetime import datetime
from a1_report_link import stage_signed_version


def commit_signed_release(*, model, db_session, exam, artifact, signer_name,
                          finance_entry=None, occurrences=(), now=None,
                          report_text=None, report_html=None, clear_revision=False):
    """Commit report metadata, clinical release, and finance in one SQL transaction.

    Caller must prepare and validate the signed PDF before invoking this function.
    On any failure, rollback the SQL session; never release an unsigned report.
    """
    if not isinstance(signer_name, str) or not signer_name.strip():
        raise ValueError("Responsável pela assinatura não identificado.")
    if getattr(exam, "status", None) == "Liberado":
        raise ValueError("Exame já liberado; revisão requer fluxo específico.")
    if getattr(exam, "signed_at", None) is not None or getattr(exam, "released_at", None) is not None:
        raise ValueError("Exame com assinatura ou liberação anterior exige revisão A1.")
    exam_id = getattr(exam, "id", None)
    if db_session.query(model).filter_by(exam_id=exam_id).first() is not None:
        raise ValueError("Exame com versão assinada exige fluxo de revisão A1.")
    moment = datetime.utcnow() if now is None else now
    if not isinstance(moment, datetime) or moment.tzinfo is not None:
        raise ValueError("Data de liberação UTC inválida.")
    if report_text is not None and (not isinstance(report_text, str) or not report_text.strip()):
        raise ValueError("Texto final do laudo inválido.")
    if report_html is not None and not isinstance(report_html, str):
        raise ValueError("HTML final do laudo inválido.")
    try:
        row = stage_signed_version(model=model, db_session=db_session,
                                   exam_id=exam_id, artifact=artifact)
        if report_text is not None:
            exam.report = report_text
        if report_html is not None:
            exam.report_html = report_html
        if clear_revision:
            exam.revision_reason = None
            exam.revision_requested_at = None
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


def commit_signed_revision(*, model, db_session, exam, artifact, signer_name,
                           report_text, report_html, now=None):
    """Atomically append a signed revision; never overwrite the original artifact.

    Caller must verify authorization and the signed artifact before invoking.
    Not connected to a clinical route.
    """
    if not isinstance(signer_name, str) or not signer_name.strip():
        raise ValueError("Responsável pela revisão não identificado.")
    if not isinstance(report_text, str) or not report_text.strip():
        raise ValueError("Texto revisado obrigatório.")
    if not isinstance(report_html, str):
        raise ValueError("HTML revisado inválido.")
    if getattr(exam, "status", None) == "Liberado":
        raise ValueError("Revisão deve estar solicitada antes da nova liberação.")
    if not isinstance(getattr(exam, "revision_reason", None), str) or not exam.revision_reason.strip():
        raise ValueError("Revisão exige justificativa registrada.")
    moment = datetime.utcnow() if now is None else now
    if not isinstance(moment, datetime) or moment.tzinfo is not None:
        raise ValueError("Data de revisão UTC inválida.")
    exam_id = getattr(exam, "id", None)
    previous = (db_session.query(model).filter_by(exam_id=exam_id)
                .order_by(model.version.desc()).first())
    if previous is None:
        raise ValueError("Revisão exige versão assinada anterior.")
    try:
        row = stage_signed_version(
            model=model, db_session=db_session, exam_id=exam_id,
            artifact=artifact, revision=True)
        exam.report = report_text
        exam.report_html = report_html
        exam.status = "Liberado"
        exam.released_at = moment
        exam.signed_at = moment
        exam.signed_by = signer_name.strip()
        exam.revision_reason = None
        exam.revision_requested_at = None
        db_session.commit()
        return row
    except Exception:
        db_session.rollback()
        raise
