import unittest
from types import SimpleNamespace
from a1_transaction import commit_signed_release


class Query:
    def filter_by(self, **kwargs): return self
    def order_by(self, *args): return self
    def first(self): return None


class Column:
    def desc(self): return self


class Model:
    version = Column()
    def __init__(self, **kwargs): self.__dict__.update(kwargs)


class Session:
    def __init__(self, fail=False):
        self.rows = []
        self.committed = False
        self.rolled_back = False
        self.fail = fail
    def query(self, model): return Query()
    def add(self, row): self.rows.append(row)
    def flush(self): pass
    def commit(self):
        if self.fail: raise RuntimeError("database unavailable")
        self.committed = True
    def rollback(self): self.rolled_back = True


def artifact():
    return dict(key="signed-reports/7/a.pdf", sha256="a"*64, size=100)


class TransactionTests(unittest.TestCase):
    def exam(self):
        return SimpleNamespace(id=7, status="A conferir", released_at=None,
                               signed_at=None, signed_by=None)

    def test_success_commits_all_changes(self):
        db = Session()
        exam = self.exam()
        occurrence = SimpleNamespace(status="Aberta", resolved_at=None)
        finance = object()
        row = commit_signed_release(model=Model, db_session=db, exam=exam,
                                    artifact=artifact(), signer_name="Dra. Marina",
                                    finance_entry=finance, occurrences=[occurrence])
        self.assertTrue(db.committed)
        self.assertFalse(db.rolled_back)
        self.assertEqual(exam.status, "Liberado")
        self.assertEqual(occurrence.status, "Resolvida")
        self.assertEqual(db.rows, [row, finance])

    def test_database_failure_rolls_back(self):
        db = Session(fail=True)
        with self.assertRaises(RuntimeError):
            commit_signed_release(model=Model, db_session=db, exam=self.exam(),
                                  artifact=artifact(), signer_name="Dra. Marina")
        self.assertTrue(db.rolled_back)
        self.assertFalse(db.committed)

    def test_invalid_artifact_never_commits(self):
        db = Session()
        with self.assertRaises(Exception):
            commit_signed_release(model=Model, db_session=db, exam=self.exam(),
                                  artifact=None, signer_name="Dra. Marina")
        self.assertTrue(db.rolled_back)
        self.assertFalse(db.committed)

    def test_previously_released_exam_rejected(self):
        db = Session()
        exam = self.exam()
        exam.status = "Liberado"
        with self.assertRaises(ValueError):
            commit_signed_release(model=Model, db_session=db, exam=exam,
                                  artifact=artifact(), signer_name="Dra. Marina")
        self.assertFalse(db.committed)


if __name__ == "__main__":
    unittest.main()
