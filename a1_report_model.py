"""Database model for exact signed report versions.

Imported by the Flask app to register the table with its SQLAlchemy metadata.
The clinical release integration must atomically commit this row with exam status.
"""


def register_signed_report_model(db):
    class SignedReport(db.Model):
        __tablename__ = "signed_report"
        id = db.Column(db.Integer, primary_key=True)
        exam_id = db.Column(db.Integer, nullable=False, index=True)
        version = db.Column(db.Integer, nullable=False)
        storage_key = db.Column(db.String(512), nullable=False, unique=True)
        sha256 = db.Column(db.String(64), nullable=False)
        size = db.Column(db.Integer, nullable=False)
        created_at = db.Column(db.DateTime, nullable=False)
        supersedes_id = db.Column(db.Integer, nullable=True)
        __table_args__ = (
            db.UniqueConstraint("exam_id", "version", name="uq_signed_report_exam_version"),
            db.CheckConstraint("version > 0", name="ck_signed_report_version_positive"),
            db.CheckConstraint("size > 0", name="ck_signed_report_size_positive"),
            db.CheckConstraint("length(sha256) = 64", name="ck_signed_report_digest_length"),
            db.CheckConstraint("storage_key LIKE 'signed-reports/%'", name="ck_signed_report_storage_prefix"),
        )

    return SignedReport
