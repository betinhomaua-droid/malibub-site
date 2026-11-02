import unittest
from a1_release_gate import ReleaseBlocked, authorize_release


class ReleaseGateTests(unittest.TestCase):
    def test_legacy_mode_is_explicit(self):
        self.assertEqual(authorize_release(a1_required=False, exam_id=3)["mode"], "legacy")

    def test_required_signature_cannot_fallback_to_unsigned(self):
        with self.assertRaises(ReleaseBlocked):
            authorize_release(a1_required=True, exam_id=3)

    def test_signed_artifact_must_match_exam(self):
        with self.assertRaises(ReleaseBlocked):
            authorize_release(a1_required=True, exam_id=3,
                              artifact={"key": "signed-reports/4/file.pdf",
                                        "sha256": "a" * 64, "size": 100})

    def test_signed_artifact_can_pass(self):
        result = authorize_release(a1_required=True, exam_id=3,
                                   artifact={"key": "signed-reports/3/file.pdf",
                                             "sha256": "a" * 64, "size": 100})
        self.assertEqual(result["mode"], "signed")

    def test_missing_integrity_blocks(self):
        with self.assertRaises(ReleaseBlocked):
            authorize_release(a1_required=True, exam_id=3,
                              artifact={"key": "signed-reports/3/file.pdf",
                                        "sha256": "invalid", "size": 100})


if __name__ == "__main__":
    unittest.main()
