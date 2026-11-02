"""Explicit ICP-Brasil trust configuration for the A1 signing pipeline.

No system default or implicit self-signed roots are accepted. Trust anchors
must be provisioned by an administrator on the server, never uploaded by clinics.
"""
import os
from pathlib import Path

from a1_signing import SignatureConfigurationError


def load_icp_brasil_validation_context(*, anchors_dir=None):
    """Load administrator-provisioned PEM/DER trust anchors, fail closed.

    Revocation checks are mandatory. This loader does not establish that the
    configured anchors are authentic ICP-Brasil roots: deployment approval must
    verify their provenance and certificate fingerprints out of band.
    """
    location = anchors_dir if anchors_dir is not None else os.getenv("MALIBUB_ICP_BRASIL_TRUST_DIR", "")
    if not isinstance(location, (str, os.PathLike)) or not str(location).strip():
        raise SignatureConfigurationError("Diretório de confiança ICP-Brasil não configurado.")
    directory = Path(location)
    if not directory.is_dir():
        raise SignatureConfigurationError("Diretório de confiança ICP-Brasil indisponível.")
    files = sorted(path for path in directory.iterdir()
                   if path.is_file() and path.suffix.lower() in (".pem", ".der", ".crt", ".cer"))
    if not files:
        raise SignatureConfigurationError("Nenhuma âncora de confiança ICP-Brasil configurada.")
    try:
        from asn1crypto import pem, x509
        from pyhanko_certvalidator import ValidationContext
        anchors = []
        for path in files:
            raw = path.read_bytes()
            if len(raw) > 1024 * 1024:
                raise ValueError("Certificado de confiança excessivamente grande.")
            if pem.detect(raw):
                _, _, raw = pem.unarmor(raw)
            cert = x509.Certificate.load(raw)
            if cert["tbs_certificate"]["subject"] != cert["tbs_certificate"]["issuer"]:
                raise ValueError("Âncora de confiança não é uma raiz autoassinada.")
            anchors.append(cert)
        return ValidationContext(trust_roots=anchors, allow_fetching=True,
                                 revocation_mode="require")
    except Exception as exc:
        raise SignatureConfigurationError("Falha na configuração da confiança ICP-Brasil.") from exc
