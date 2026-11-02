import unittest
from io import BytesIO
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from reportlab.pdfgen import canvas
from a1_signing import sign_pdf_pades, verify_embedded_signature, validate_signer_trust, SignatureConfigurationError


class A1SigningTests(unittest.TestCase):
    def test_sign_and_verify_with_ephemeral_test_certificate(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'CERTIFICADO FICTICIO TESTE')])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=1))
                .sign(key, hashes.SHA256()))
        pfx = pkcs12.serialize_key_and_certificates(
            b'test', key, cert, None,
            serialization.BestAvailableEncryption(b'test-password'))
        stream = BytesIO()
        pdf = canvas.Canvas(stream)
        pdf.drawString(70, 760, 'PDF FICTICIO - SEM DADOS DE PACIENTES')
        pdf.save()
        original = stream.getvalue()
        signed = sign_pdf_pades(original, pfx, 'test-password')
        self.assertNotEqual(original, signed)
        self.assertTrue(verify_embedded_signature(signed))
        self.assertFalse(verify_embedded_signature(original))
        # Modifying signed bytes must fail integrity verification.
        altered = signed.replace(b'PDF FICTICIO', b'PDF ALTERADO')
        if altered == signed:
            altered = signed[:-30] + bytes([signed[-30] ^ 1]) + signed[-29:]
        self.assertFalse(verify_embedded_signature(altered))

    def test_requires_explicit_trust_context(self):
        with self.assertRaises(SignatureConfigurationError):
            validate_signer_trust(b'%PDF-1.7', None)

    def test_rejects_non_pdf(self):
        with self.assertRaises(ValueError):
            sign_pdf_pades(b"not a PDF", b"cert", "password")

    def test_rejects_missing_certificate(self):
        with self.assertRaises(SignatureConfigurationError):
            sign_pdf_pades(b"%PDF-1.7", b"", "password")

    def test_rejects_missing_password(self):
        with self.assertRaises(SignatureConfigurationError):
            sign_pdf_pades(b"%PDF-1.7", b"cert", "")


if __name__ == "__main__":
    unittest.main()
