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

    def test_upload_expiry_policy_unchanged(self):
        self.assertEqual(SOURCE.count("<=1800"), 2)
        self.assertIn("DIRECT_UPLOAD_SIGNER.loads(token,max_age=1800)", SOURCE)
        self.assertIn("ExpiresIn=900", SOURCE)

    def test_admin_unlock_is_post_only_and_csrf_protected(self):
        self.assertIn('@app.route("/admin/usuarios/<int:uid>/desbloquear",methods=["POST"])', SOURCE)
        self.assertIn('def admin_unlock_clinic(uid):', SOURCE)
        self.assertIn('u.access_locked=False', SOURCE)
        self.assertIn('u.failed_login_count=0', SOURCE)
        self.assertIn("action='/admin/usuarios/{u.id}/desbloquear'", SOURCE)
        self.assertIn("{csrf_field()}<button type='submit' {'disabled' if not u.access_locked else ''}>Desbloquear</button>", SOURCE)

    def test_three_attempt_clinic_lock(self):
        self.assertIn('if u.failed_login_count>=3:', SOURCE)
        self.assertIn('CONTATE A MALIBUB PELO WHATSAPP.', SOURCE)

    def test_clinic_revision_modal(self):
        self.assertIn('function openRevisionDialog(el)', SOURCE)
        self.assertIn('dlg.showModal()', SOURCE)
        self.assertIn('name="revision_reason" minlength="10" maxlength="2000"', SOURCE)
        self.assertIn('''+ csrf_field() +''', SOURCE)
        self.assertIn('Exam.query.filter_by(id=eid,clinic_id=session["uid"]).first_or_404()', SOURCE)
        self.assertIn('e.status="Revisão solicitada"', SOURCE)
        self.assertIn('Revisão solicitada pela clínica', SOURCE)
        self.assertIn('if e.status=="Revisão solicitada" and existing_revenue:', SOURCE)

if __name__ == "__main__":
    unittest.main()
