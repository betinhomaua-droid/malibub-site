"""Integration tests for all-or-nothing clinical A1 release using SQLite."""
import unittest
from datetime import datetime
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from a1_report_model import register_signed_report_model
from a1_transaction import commit_signed_release, commit_signed_revision
from a1_report_link import stage_signed_version


class SignedReleaseDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        self.db = SQLAlchemy(self.app)
        db = self.db

        class Exam(db.Model):
            id = db.Column(db.Integer, primary_key=True)
            status = db.Column(db.String(64), nullable=False)
            released_at = db.Column(db.DateTime)
            signed_at = db.Column(db.DateTime)
            signed_by = db.Column(db.String(128))
            report = db.Column(db.Text)
            report_html = db.Column(db.Text)
            revision_reason = db.Column(db.Text)
            revision_requested_at = db.Column(db.DateTime)

        class Finance(db.Model):
            id = db.Column(db.Integer, primary_key=True)
            description = db.Column(db.String(128), unique=True, nullable=False)

        class Occurrence(db.Model):
            id = db.Column(db.Integer, primary_key=True)
            status = db.Column(db.String(64), nullable=False)
            resolved_at = db.Column(db.DateTime)

        self.Exam, self.Finance, self.Occurrence = Exam, Finance, Occurrence
        self.SignedReport = register_signed_report_model(db)
        self.context = self.app.app_context()
        self.context.push()
        db.create_all()
        db.session.add_all([
            Exam(id=7, status="A conferir"),
            Occurrence(id=9, status="Aberta"),
            Finance(description="Laudo existente"),
        ])
        db.session.commit()

    def tearDown(self):
        self.db.session.remove()
        self.db.drop_all()
        self.context.pop()

    def artifact(self):
        return {"key": "signed-reports/7/test.pdf", "sha256": "a" * 64, "size": 123}

    def test_success_persists_release_finance_occurrence_and_version(self):
        exam = self.db.session.get(self.Exam, 7)
        occurrence = self.db.session.get(self.Occurrence, 9)
        commit_signed_release(
            model=self.SignedReport, db_session=self.db.session,
            exam=exam, artifact=self.artifact(), signer_name="Dra. Marina",
            finance_entry=self.Finance(description="Laudo novo"),
            occurrences=[occurrence], now=datetime(2026, 11, 2),
        )
        self.db.session.expire_all()
        self.assertEqual(self.db.session.get(self.Exam, 7).status, "Liberado")
        self.assertEqual(self.db.session.get(self.Occurrence, 9).status, "Resolvida")
        self.assertEqual(self.SignedReport.query.count(), 1)
        self.assertEqual(self.Finance.query.count(), 2)

    def test_prior_signed_exam_is_rejected_without_sql_changes(self):
        exam = self.db.session.get(self.Exam, 7)
        exam.signed_at = datetime(2026, 11, 1)
        self.db.session.commit()
        with self.assertRaisesRegex(ValueError, "revisão A1"):
            commit_signed_release(
                model=self.SignedReport, db_session=self.db.session,
                exam=exam, artifact=self.artifact(), signer_name="Dra. Marina",
            )
        self.db.session.expire_all()
        self.assertEqual(self.db.session.get(self.Exam, 7).status, "A conferir")
        self.assertEqual(self.SignedReport.query.count(), 0)

    def test_prior_released_exam_is_rejected_without_sql_changes(self):
        exam = self.db.session.get(self.Exam, 7)
        exam.released_at = datetime(2026, 11, 1)
        self.db.session.commit()
        with self.assertRaisesRegex(ValueError, "revisão A1"):
            commit_signed_release(
                model=self.SignedReport, db_session=self.db.session,
                exam=exam, artifact=self.artifact(), signer_name="Dra. Marina",
            )
        self.db.session.expire_all()
        self.assertEqual(self.db.session.get(self.Exam, 7).status, "A conferir")
        self.assertEqual(self.SignedReport.query.count(), 0)

    def test_existing_signed_version_blocks_first_release_even_without_dates(self):
        exam = self.db.session.get(self.Exam, 7)
        self.SignedReport.query.delete()
        self.db.session.add(self.SignedReport(
            exam_id=7, version=1, storage_key="signed-reports/7/previous.pdf",
            sha256="b" * 64, size=123, created_at=datetime(2026, 11, 1),
        ))
        self.db.session.commit()
        with self.assertRaisesRegex(ValueError, "revisão A1"):
            commit_signed_release(
                model=self.SignedReport, db_session=self.db.session,
                exam=exam, artifact=self.artifact(), signer_name="Dra. Marina",
            )
        self.db.session.expire_all()
        self.assertEqual(self.db.session.get(self.Exam, 7).status, "A conferir")
        self.assertEqual(self.SignedReport.query.count(), 1)

    def test_revision_version_links_to_immutable_previous_version(self):
        first = stage_signed_version(
            model=self.SignedReport, db_session=self.db.session,
            exam_id=7, artifact=self.artifact())
        self.db.session.commit()
        original_key = first.storage_key
        second = stage_signed_version(
            model=self.SignedReport, db_session=self.db.session,
            exam_id=7, artifact={
                "key": "signed-reports/7/revision.pdf",
                "sha256": "b" * 64, "size": 456,
            }, revision=True)
        self.db.session.commit()
        self.assertEqual(second.version, 2)
        self.assertEqual(second.supersedes_id, first.id)
        self.assertEqual(self.db.session.get(self.SignedReport, first.id).storage_key, original_key)

    def test_revision_without_prior_signed_version_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "versão assinada anterior"):
            stage_signed_version(
                model=self.SignedReport, db_session=self.db.session,
                exam_id=7, artifact=self.artifact(), revision=True)
        self.assertEqual(self.SignedReport.query.count(), 0)

    def test_first_release_cannot_append_to_existing_signed_history(self):
        stage_signed_version(
            model=self.SignedReport, db_session=self.db.session,
            exam_id=7, artifact=self.artifact())
        self.db.session.commit()
        with self.assertRaisesRegex(ValueError, "revisão A1"):
            stage_signed_version(
                model=self.SignedReport, db_session=self.db.session,
                exam_id=7, artifact={
                    "key": "signed-reports/7/second.pdf",
                    "sha256": "b" * 64, "size": 456,
                })
        self.assertEqual(self.SignedReport.query.count(), 1)

    def test_revision_transaction_preserves_original_and_updates_report(self):
        exam = self.db.session.get(self.Exam, 7)
        exam.revision_reason = "Correção solicitada pela clínica"
        self.db.session.add(self.SignedReport(
            exam_id=7, version=1, storage_key="signed-reports/7/original.pdf",
            sha256="a" * 64, size=123, created_at=datetime(2026, 11, 1)))
        self.db.session.commit()
        revised = commit_signed_revision(
            model=self.SignedReport, db_session=self.db.session,
            exam=exam, artifact={
                "key": "signed-reports/7/revised.pdf",
                "sha256": "b" * 64, "size": 456},
            signer_name="Dra. Marina", report_text="Texto corrigido",
            report_html="<p>Texto corrigido</p>", now=datetime(2026, 11, 2))
        self.assertEqual(revised.version, 2)
        self.assertEqual(self.db.session.get(self.SignedReport, revised.supersedes_id).storage_key,
                         "signed-reports/7/original.pdf")
        self.assertEqual(exam.report, "Texto corrigido")
        self.assertIsNone(exam.revision_reason)
        self.assertEqual(self.SignedReport.query.count(), 2)

    def test_revision_database_commit_failure_restores_original_metadata(self):
        exam = self.db.session.get(self.Exam, 7)
        exam.revision_reason = "Correção solicitada"
        exam.report = "Texto original"
        exam.report_html = "<p>Texto original</p>"
        self.db.session.add(self.SignedReport(
            exam_id=7, version=1, storage_key="signed-reports/7/original.pdf",
            sha256="a" * 64, size=123, created_at=datetime(2026, 11, 1)))
        self.db.session.commit()
        original_commit = self.db.session.commit
        def fail_commit():
            raise RuntimeError("Falha simulada no commit")
        self.db.session.commit = fail_commit
        try:
            with self.assertRaisesRegex(RuntimeError, "Falha simulada"):
                commit_signed_revision(
                    model=self.SignedReport, db_session=self.db.session,
                    exam=exam, artifact={
                        "key": "signed-reports/7/revised.pdf",
                        "sha256": "b" * 64, "size": 456},
                    signer_name="Dra. Marina", report_text="Texto novo",
                    report_html="<p>Texto novo</p>")
        finally:
            self.db.session.commit = original_commit
        self.db.session.expire_all()
        exam = self.db.session.get(self.Exam, 7)
        self.assertEqual(exam.report, "Texto original")
        self.assertEqual(exam.report_html, "<p>Texto original</p>")
        self.assertEqual(exam.revision_reason, "Correção solicitada")
        self.assertEqual(exam.status, "A conferir")
        self.assertEqual(self.SignedReport.query.count(), 1)

    def test_revision_without_reason_does_not_create_version(self):
        exam = self.db.session.get(self.Exam, 7)
        with self.assertRaisesRegex(ValueError, "justificativa"):
            commit_signed_revision(
                model=self.SignedReport, db_session=self.db.session,
                exam=exam, artifact=self.artifact(), signer_name="Dra. Marina",
                report_text="Texto", report_html="<p>Texto</p>")
        self.assertEqual(self.SignedReport.query.count(), 0)

    def test_finance_constraint_failure_rolls_back_everything(self):
        exam = self.db.session.get(self.Exam, 7)
        occurrence = self.db.session.get(self.Occurrence, 9)
        with self.assertRaises(IntegrityError):
            commit_signed_release(
                model=self.SignedReport, db_session=self.db.session,
                exam=exam, artifact=self.artifact(), signer_name="Dra. Marina",
                finance_entry=self.Finance(description="Laudo existente"),
                occurrences=[occurrence],
            )
        self.db.session.expire_all()
        self.assertEqual(self.db.session.get(self.Exam, 7).status, "A conferir")
        self.assertIsNone(self.db.session.get(self.Exam, 7).signed_at)
        self.assertEqual(self.db.session.get(self.Occurrence, 9).status, "Aberta")
        self.assertEqual(self.SignedReport.query.count(), 0)
        self.assertEqual(self.Finance.query.count(), 1)


if __name__ == "__main__":
    unittest.main()
