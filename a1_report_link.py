"""Database-side linkage for signed report artifacts.

Call only after prepare_signed_report() has validated and stored signed bytes.
Caller must commit this row and exam release in one transaction. The storage
write is external and must be reconciled if database commit fails.
"""
from datetime import datetime
from a1_release_gate import authorize_release


def stage_signed_version(*, model, db_session, exam_id, artifact):
    decision = authorize_release(a1_required=True, exam_id=exam_id, artifact=artifact)
    previous = (db_session.query(model).filter_by(exam_id=exam_id)
                .order_by(model.version.desc()).first())
    if previous is not None and (not isinstance(previous.version, int) or isinstance(previous.version, bool) or previous.version < 1):
        raise ValueError("Histórico de versões assinadas inconsistente.")
    version = (previous.version + 1) if previous else 1
    row = model(
        exam_id=exam_id, version=version,
        storage_key=decision["artifact"]["key"],
        sha256=decision["artifact"]["sha256"],
        size=decision["artifact"]["size"],
        created_at=datetime.utcnow(),
        supersedes_id=previous.id if previous else None,
    )
    db_session.add(row)
    db_session.flush()
    return row
