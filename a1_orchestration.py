"""Orchestrate A1 signing before a single clinical database release.

This is deliberately not attached to Flask routes yet. The PDF builder must
produce final bytes without changing clinical status; the caller must perform
signer authorization before invoking it.
"""
from datetime import datetime
from a1_pipeline import prepare_signed_report
from a1_signing import SignatureValidationError


def validate_unsigned_pdf(pdf_bytes):
    """Reject truncated, encrypted, empty or malformed source documents."""
    if not isinstance(pdf_bytes, bytes) or not pdf_bytes.startswith(b"%PDF-"):
        raise SignatureValidationError("Gerador não produziu um PDF válido para assinatura.")
    try:
        import io
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(pdf_bytes), strict=True)
        if reader.is_encrypted or len(reader.pages) == 0:
            raise ValueError("Documento vazio ou criptografado.")
        for page in reader.pages:
            _ = page.mediabox
    except Exception:
        raise SignatureValidationError("PDF de origem não passou na validação estrutural.") from None
    return pdf_bytes
from a1_transaction import commit_signed_release


def sign_and_release(*, pdf_builder, model, db_session, exam, signer_name,
                     storage_client, bucket, validation_context, authorized=False,
                     finance_entry=None, occurrences=(), signing_at=None,
                     report_text=None, report_html=None, clear_revision=False,
                     signing_pipeline=prepare_signed_report,
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
    if signing_at is None:
        signing_at = datetime.utcnow()
    if not isinstance(signing_at, datetime) or signing_at.tzinfo is not None:
        raise ValueError("Data de assinatura deve ser datetime UTC sem timezone.")
    built = pdf_builder(signer_name=signer_name.strip(), signing_at=signing_at)
    if isinstance(built, tuple):
        if len(built) != 3 or not isinstance(built[1], str) or not built[1].strip() or not isinstance(built[2], str):
            raise ValueError("Gerador A1 retornou conteúdo inconsistente.")
        pdf_bytes, prepared_text, prepared_html = built
        if report_text is not None and report_text != prepared_text:
            raise ValueError("Texto final diverge do conteúdo usado no PDF.")
        if report_html is not None and report_html != prepared_html:
            raise ValueError("HTML final diverge do conteúdo usado no PDF.")
        report_text, report_html = prepared_text, prepared_html
    else:
        if report_text is not None or report_html is not None:
            raise ValueError("Laudo final exige preparação vinculada de PDF, texto e HTML.")
        pdf_bytes = built
    validate_unsigned_pdf(pdf_bytes)
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
        finance_entry=finance_entry, occurrences=occurrences, now=signing_at,
        report_text=report_text, report_html=report_html,
        clear_revision=clear_revision,
    )
