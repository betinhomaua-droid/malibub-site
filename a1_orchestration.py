"""Orchestrate A1 signing before a single clinical database release.

This is deliberately not attached to Flask routes yet. The PDF builder must
produce final bytes without changing clinical status; the caller must perform
signer authorization before invoking it.
"""
from a1_pipeline import prepare_signed_report
from a1_transaction import commit_signed_release


def sign_and_release(*, pdf_builder, model, db_session, exam, signer_name,
                     storage_client, bucket, validation_context, authorized=False,
                     finance_entry=None, occurrences=(), signing_pipeline=prepare_signed_report,
                     transaction=commit_signed_release):
    if authorized is not True:
        raise PermissionError("Radiologista não autorizada a liberar este exame.")
    if not isinstance(signer_name, str) or not signer_name.strip():
        raise ValueError("Responsável pela assinatura não identificado.")
    if storage_client is None or not bucket or validation_context is None:
        raise ValueError("Armazenamento ou validação ICP-Brasil indisponível.")
    if not callable(pdf_builder):
        raise TypeError("Gerador de PDF final indisponível.")
    exam_id = getattr(exam, "id", None)
    if not isinstance(exam_id, int) or isinstance(exam_id, bool) or exam_id <= 0:
        raise ValueError("Identificação do exame inválida.")
    if getattr(exam, "status", None) == "Liberado":
        raise ValueError("Exame já liberado; revisão exige fluxo próprio.")
    pdf_bytes = pdf_builder()
    artifact = signing_pipeline(
        pdf_bytes=pdf_bytes, exam_id=exam_id,
        storage_client=storage_client, bucket=bucket,
        validation_context=validation_context, authorized=True,
    )
    # Object storage is not transactional with SQL. A failed commit leaves an
    # unreferenced private artifact, which must be reconciled asynchronously.
    # Never delete here: a commit can succeed while its acknowledgement fails.
    return transaction(
        model=model, db_session=db_session, exam=exam,
        artifact=artifact, signer_name=signer_name,
        finance_entry=finance_entry, occurrences=occurrences,
    )
