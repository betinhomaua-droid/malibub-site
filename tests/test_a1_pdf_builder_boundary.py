"""Regression checks for the HTTP-independent PDF builder extraction.

These checks do not replace live render tests with clinic models.
"""
import ast
import pathlib
import unittest


SOURCE = pathlib.Path(__file__).resolve().parents[1] / "app.py"


class PdfBuilderBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        cls.functions = {n.name: n for n in cls.tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}

    def test_pdf_builder_exists_and_is_not_a_route(self):
        builder = self.functions["build_legacy_report_pdf_bytes"]
        self.assertEqual(builder.decorator_list, [])
        self.assertEqual([a.arg for a in builder.args.args], ["e"])

    def test_pdf_builder_does_not_read_http_request_or_session(self):
        builder = self.functions["build_legacy_report_pdf_bytes"]
        names = {n.id for n in ast.walk(builder) if isinstance(n, ast.Name)}
        self.assertFalse(names.intersection({"request", "session", "send_file", "redirect", "Response"}))

    def test_authorized_route_still_checks_access_and_signed_versions(self):
        route = ast.get_source_segment(SOURCE.read_text(encoding="utf-8"), self.functions["result_pdf"])
        self.assertIn('session.get("uid")', route)
        self.assertIn('session.get("role")', route)
        self.assertIn("SignedReport.query", route)
        self.assertIn("render_legacy_report_pdf_response(e)", route)

    def test_download_wrapper_uses_shared_builder(self):
        wrapper = ast.get_source_segment(SOURCE.read_text(encoding="utf-8"), self.functions["render_legacy_report_pdf_response"])
        self.assertIn("build_legacy_report_pdf_bytes(e)", wrapper)
        self.assertIn("send_file(io.BytesIO(pdf_bytes)", wrapper)

    def test_temporary_model_cleanup_runs_in_finally(self):
        builder = self.functions["build_legacy_report_pdf_bytes"]
        finally_blocks = [n.finalbody for n in ast.walk(builder) if isinstance(n, ast.Try) and n.finalbody]
        self.assertTrue(finally_blocks, "Temporary clinic PDF must be cleaned even on failure")
        self.assertTrue(any(
            any(isinstance(node, ast.Attribute) and node.attr == "unlink"
                for statement in block for node in ast.walk(statement))
            for block in finally_blocks
        ), "Temporary model must be unlinked in finally")

    def test_builder_covers_standard_tmj_and_custom_pdf(self):
        builder = ast.get_source_segment(SOURCE.read_text(encoding="utf-8"), self.functions["build_legacy_report_pdf_bytes"])
        self.assertIn("tdoc.build(story_tmj)", builder)
        self.assertIn("doc.build(", builder)
        self.assertIn("has_pdf_model", builder)
        self.assertIn("temp_model_path", builder)


if __name__ == "__main__":
    unittest.main()
