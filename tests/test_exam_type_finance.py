import os
import tempfile
import unittest

os.environ["APP_ENV"] = "test"
os.environ.pop("DATABASE_URL", None)
import app as mod


class ExamTypeFinanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        mod.app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + self.tmp.name + "/test.db"
        mod.app.config["TESTING"] = True
        mod._initialized = False
        self.ctx = mod.app.app_context()
        self.ctx.push()
        mod.db.session.remove()
        mod.db.engine.dispose()
        mod.db.create_all()
        self.clinic = mod.User(name="Clínica Teste", role="Clinica")
        self.radiologist = mod.User(name="Marina", role="Radiologista")
        mod.db.session.add_all([self.clinic, self.radiologist])
        mod.db.session.flush()
        mod.db.session.add_all([
            mod.ClinicPrice(clinic_id=self.clinic.id, exam_type="Tipo A", amount=100, active=True),
            mod.ClinicPrice(clinic_id=self.clinic.id, exam_type="Tipo B", amount=80, active=True),
            mod.ClinicPrice(clinic_id=self.clinic.id, exam_type="Inativo", amount=40, active=False),
        ])
        self.exam = mod.Exam(protocol="2600001", patient="Paciente Teste", clinic_id=self.clinic.id,
                             exam_type="Tipo A", contracted_amount=100, priority="NORMAL", status="Aguardando laudo")
        mod.db.session.add(self.exam)
        mod.db.session.commit()
        self.eid = self.exam.id
        self.client = mod.app.test_client()
        with self.client.session_transaction() as s:
            s["uid"] = self.radiologist.id
            s["role"] = "Radiologista"
            s["_csrf_token"] = "testtoken"

    def tearDown(self):
        mod.db.session.remove()
        mod.db.drop_all()
        self.ctx.pop()
        self.tmp.cleanup()

    def post(self, typ):
        return self.client.post(f"/exam/{self.eid}/editar-tipo",
                                data={"exam_type": typ, "_csrf_token": "testtoken"})

    def test_normal_price_and_audit(self):
        self.assertEqual(self.post("Tipo B").status_code, 302)
        e = mod.db.session.get(mod.Exam, self.eid)
        self.assertEqual((e.exam_type, e.contracted_amount, e.protocol), ("Tipo B", 80, "2600001"))
        change = mod.ExamTypeChange.query.one()
        self.assertEqual((change.old_type, change.new_type, change.old_amount, change.new_amount),
                         ("Tipo A", "Tipo B", 100, 80))

    def test_urgent_price(self):
        self.exam.priority = "URG"
        self.exam.contracted_amount = 150
        mod.db.session.commit()
        self.post("Tipo B")
        self.assertEqual(mod.db.session.get(mod.Exam, self.eid).contracted_amount, 120)

    def test_inactive_type_rejected(self):
        self.post("Inativo")
        self.assertEqual(mod.db.session.get(mod.Exam, self.eid).exam_type, "Tipo A")
        self.assertEqual(mod.ExamTypeChange.query.count(), 0)

    def test_released_exam_blocked(self):
        self.exam.status = "Liberado"
        mod.db.session.commit()
        self.post("Tipo B")
        self.assertEqual(mod.db.session.get(mod.Exam, self.eid).exam_type, "Tipo A")

    def test_finance_entry_blocks_change(self):
        mod.db.session.add(mod.Finance(description="Laudo 2600001", kind="Entrada", amount=100))
        mod.db.session.commit()
        self.post("Tipo B")
        self.assertEqual(mod.db.session.get(mod.Exam, self.eid).exam_type, "Tipo A")

    def test_clinic_cannot_edit(self):
        with self.client.session_transaction() as s:
            s["uid"] = self.clinic.id
            s["role"] = "Clinica"
        self.post("Tipo B")
        self.assertEqual(mod.db.session.get(mod.Exam, self.eid).exam_type, "Tipo A")


if __name__ == "__main__":
    unittest.main()
