"""Server-side A1 secret access; never expose this module to client routes.

Provision the PFX as a Render secret file and its passphrase as a protected
environment secret. Never commit, print, upload through a public form, or
include the credentials in exception messages.
"""
import os
from pathlib import Path
from a1_signing import SignatureConfigurationError


def load_a1_credentials(*, certificate_path=None, password=None):
    """Load credentials only from server-side configuration.

    The production caller must enforce radiologist identity and authorization.
    No default paths, fallback credentials, or interactive upload are allowed.
    """
    path_value = certificate_path if certificate_path is not None else os.environ.get("MALIBUB_A1_PFX_PATH")
    secret = password if password is not None else os.environ.get("MALIBUB_A1_PFX_PASSWORD")
    if not path_value or not secret:
        raise SignatureConfigurationError("Configuração segura do certificado A1 incompleta.")
    path = Path(path_value)
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise SignatureConfigurationError("Arquivo protegido do certificado A1 indisponível.")
    try:
        if path.stat().st_size > 1024 * 1024:
            raise SignatureConfigurationError("Arquivo A1 excede o limite permitido.")
        data = path.read_bytes()
    except OSError as exc:
        raise SignatureConfigurationError("Não foi possível ler o certificado A1.") from None
    if not data:
        raise SignatureConfigurationError("Certificado A1 vazio.")
    return data, secret
