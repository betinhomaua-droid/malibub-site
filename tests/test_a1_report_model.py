"""Exercise the actual signed-report SQL constraints against SQLite."""
import unittest
from datetime import datetime
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from a1_report_model import register_signed_report_model


class SignedReportDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        self.db = SQLAlchemy(self.app)
        self.model = register_signed_report_model(self.db)
        self.context = self.app.app_context()
        self.context.push()
        self.db.create_all()

    def tearDown(self):
        self.db.session.remove()
        self.db.drop_all()
        self.context.pop()

    def insert(self, **overrides):
        values = dict(exam_id=7, version=1, storage_key="signed-reports/7/a.pdf",
                      sha256="a" * 64, size=123, created_at=datetime.utcnow())
        values.update(overrides)
        self.db.session.add(self.model(**values))
        self.db.session.commit()

    def test_valid_record(self):
        self.insert()
        self.assertEqual(self.model.query.count(), 1)

    def test_invalid_version(self):
        with self.assertRaises(IntegrityError):
            self.insert(version=0)

    def test_invalid_size(self):
        with self.assertRaises(IntegrityError):
            self.insert(size=0)

    def test_invalid_digest_length(self):
        with self.assertRaises(IntegrityError):
            self.insert(sha256="a" * 63)

    def test_invalid_storage_namespace(self):
        with self.assertRaises(IntegrityError):
            self.insert(storage_key="other/7/a.pdf")

    def test_empty_storage_object_name(self):
        with self.assertRaises(IntegrityError):
            self.insert(storage_key="signed-reports/")

    def test_duplicate_exam_version(self):
        self.insert()
        with self.assertRaises(IntegrityError):
            self.insert(storage_key="signed-reports/7/b.pdf")

    def test_duplicate_storage_key(self):
        self.insert()
        with self.assertRaises(IntegrityError):
            self.insert(exam_id=8)


if __name__ == "__main__":
    unittest.main()
