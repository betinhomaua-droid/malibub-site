import pathlib
import unittest

SOURCE = pathlib.Path(__file__).resolve().parents[1].joinpath("app.py").read_text(encoding="utf-8")

class SecuritySourceChecks(unittest.TestCase):
    def test_turnstile_server_validation(self):
        self.assertIn("https://challenges.cloudflare.com/turnstile/v0/siteverify", SOURCE)
        self.assertIn('if not verify_turnstile(data.get("turnstile_token","")):', SOURCE)

    def test_direct_upload_proof_and_expiry(self):
        self.assertIn('def direct_upload_url():', SOURCE)
        self.assertIn('def direct_upload_finalize():', SOURCE)
        self.assertGreaterEqual(SOURCE.count('session.get("turnstile_proof_at")'), 2)

    def test_no_fixed_250mb_cap(self):
        self.assertNotIn("DIRECT_UPLOAD_MAX_BYTES", SOURCE)
        self.assertIn('if size<=0: raise ValueError("empty upload")', SOURCE)

    def test_three_attempt_clinic_lock(self):
        self.assertIn('if u.failed_login_count>=3:', SOURCE)
        self.assertIn('CONTATE A MALIBUB PELO WHATSAPP.', SOURCE)

if __name__ == "__main__":
    unittest.main()
