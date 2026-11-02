import unittest
from a1_revisions import SignedReportVersion, new_signed_version, resolve_revision


class SignedRevisionTests(unittest.TestCase):
    def setUp(self):
        self.v1 = new_signed_version(previous=None, storage_key="signed-reports/7/v1.pdf",
                                     sha256="a" * 64)

    def test_first_version(self):
        self.assertEqual(self.v1.number, 1)
        self.assertIsNone(self.v1.supersedes)

    def test_new_version_preserves_previous(self):
        v2 = new_signed_version(previous=self.v1, storage_key="signed-reports/7/v2.pdf",
                                sha256="b" * 64)
        outcome = resolve_revision(previous=self.v1, decision="replace",
                                   justification="Correção do achado", replacement=v2)
        self.assertEqual(outcome["current"].number, 2)
        self.assertEqual(self.v1.number, 1)
        self.assertEqual(v2.supersedes, 1)

    def test_maintain_original(self):
        outcome = resolve_revision(previous=self.v1, decision="maintain",
                                   justification="Revisão sem alterações")
        self.assertIs(outcome["current"], self.v1)

    def test_justification_required(self):
        with self.assertRaises(ValueError):
            resolve_revision(previous=self.v1, decision="maintain", justification=" ")

    def test_cannot_overwrite_old_version(self):
        v2 = new_signed_version(previous=self.v1, storage_key=self.v1.storage_key,
                                sha256="b" * 64)
        with self.assertRaises(ValueError):
            resolve_revision(previous=self.v1, decision="replace",
                             justification="Correção", replacement=v2)

    def test_cannot_claim_replacement_with_identical_pdf(self):
        v2 = new_signed_version(previous=self.v1, storage_key="signed-reports/7/v2.pdf",
                                sha256=self.v1.sha256)
        with self.assertRaises(ValueError):
            resolve_revision(previous=self.v1, decision="replace",
                             justification="Correção", replacement=v2)

    def test_cannot_skip_versions(self):
        bad = SignedReportVersion(number=4, storage_key="signed-reports/7/v4.pdf",
                                  sha256="b" * 64, signed_at=self.v1.signed_at,
                                  supersedes=1)
        with self.assertRaises(ValueError):
            resolve_revision(previous=self.v1, decision="replace",
                             justification="Correção", replacement=bad)


if __name__ == "__main__":
    unittest.main()
