import unittest
from types import SimpleNamespace
from a1_report_link import stage_signed_version
from a1_release_gate import ReleaseBlocked


class Query:
    def __init__(self, previous): self.previous = previous
    def filter_by(self, **kwargs): return self
    def order_by(self, *args): return self
    def first(self): return self.previous


class Column:
    def desc(self): return self


class Model:
    version = Column()
    def __init__(self, **kwargs): self.__dict__.update(kwargs)


class Session:
    def __init__(self, previous=None): self.previous = previous; self.rows = []
    def query(self, model): return Query(self.previous)
    def add(self, row): self.rows.append(row)
    def flush(self): pass


def artifact(exam_id):
    return {"key": f"signed-reports/{exam_id}/random.pdf", "sha256": "a" * 64, "size": 123}


class LinkTests(unittest.TestCase):
    def test_initial_version(self):
        db = Session()
        row = stage_signed_version(model=Model, db_session=db, exam_id=7, artifact=artifact(7))
        self.assertEqual(row.version, 1)
        self.assertIsNone(row.supersedes_id)
        self.assertEqual(db.rows, [row])

    def test_revision_links_previous(self):
        db = Session(SimpleNamespace(version=2, id=18))
        row = stage_signed_version(model=Model, db_session=db, exam_id=7, artifact=artifact(7))
        self.assertEqual((row.version, row.supersedes_id), (3, 18))

    def test_corrupted_version_history_does_not_write(self):
        for version in (0, -1, True, "2"):
            with self.subTest(version=version):
                db = Session(SimpleNamespace(version=version, id=18))
                with self.assertRaises(ValueError):
                    stage_signed_version(model=Model, db_session=db, exam_id=7, artifact=artifact(7))
                self.assertEqual(db.rows, [])

    def test_wrong_exam_does_not_write(self):
        db = Session()
        with self.assertRaises(ReleaseBlocked):
            stage_signed_version(model=Model, db_session=db, exam_id=7, artifact=artifact(8))
        self.assertEqual(db.rows, [])


if __name__ == "__main__":
    unittest.main()
