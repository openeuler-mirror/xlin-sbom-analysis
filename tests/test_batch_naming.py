import argparse
import os
import re
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

import actions.reporter

_pkg_reporter_stub = types.ModuleType(
    "actions.reporter.docx_reporter_pkg")
_pkg_reporter_stub.generate_docx_report = lambda *args, **kwargs: (
    object(), [], "同意引入")
sys.modules["actions.reporter.docx_reporter_pkg"] = _pkg_reporter_stub
actions.reporter.docx_reporter_pkg = _pkg_reporter_stub

import actions.scanner.batch_helper as batch_helper


class BatchNamingTests(unittest.TestCase):
    timestamp = "20261022153000"

    def setUp(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        self.output_base = self._temp_dir.name

    def tearDown(self):
        self._temp_dir.cleanup()

    def test_batch_output_uses_separate_folder_and_file_names(self):
        row = {
            "name": "foo",
            "version": "1.0",
            "type": "git",
            "path": "https://github.com/example/foo.git",
        }
        args = argparse.Namespace(
            output=self.output_base,
            max_workers=1,
            disable_tqdm=True,
        )
        config = {"general": {}}

        with patch.object(
                batch_helper, "_scan_source_code", return_value=[]), \
                patch.object(
                    batch_helper,
                    "_add_vulnerabilities_to_package",
                    return_value={}), \
                patch.object(
                    batch_helper.pkg_docx,
                    "generate_docx_report",
                    return_value=(object(), [], "同意引入")), \
                patch.object(
                    batch_helper, "save_docx_report") as save_docx, \
                patch.object(
                    batch_helper, "convert_docx_to_pdf"):
            package, error = batch_helper._process_package_from_row(
                row, args, self.timestamp, config)

        self.assertIsNotNone(package)
        self.assertIsNone(error)

        output_dir = os.path.join(
            self.output_base, f"foo-1.0_{self.timestamp}")
        self.assertTrue(os.path.isdir(output_dir))

        saved_path = save_docx.call_args[0][1]
        self.assertEqual(
            os.path.basename(saved_path),
            "foo-1.0 安全引入评估报告.docx",
        )
        self.assertEqual(os.path.dirname(saved_path), output_dir)
        self.assertIsNone(re.search(r"\d{14}", os.path.basename(saved_path)))


if __name__ == "__main__":
    unittest.main()
