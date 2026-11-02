"""Integration tests for all-or-nothing clinical A1 release using SQLite."""
import unittest
from datetime import datetime
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from a1_report_model import register_signed_report_model
from a1_transaction import commit_signed_release


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
