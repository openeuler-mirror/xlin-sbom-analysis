import os
import re
import tempfile
import unittest
import zipfile

import actions.reporter.docx_reporter_repo as repo_docx
from actions.data_helper import (
    convert_docx_to_pdf,
    save_docx_report,
    setup_paths,
)
from actions.package import Package
from actions.scanner.repo_helper import _format_target_name


class RepoReportNamingTests(unittest.TestCase):
    timestamp = "20261022153000"
    distro_name = "openEuler-24.03-LTS-SP1"

    def setUp(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        self.output_base = self._temp_dir.name
        self.target_name = _format_target_name(self.distro_name, "2026-10-22")
        self.paths = setup_paths(
            self.output_base,
            self.distro_name,
            self.timestamp,
            self.target_name,
        )

    def tearDown(self):
        self._temp_dir.cleanup()

    def _config(self):
        return {
            "general": {
                "report_version": "V1.0",
                "author": "Test",
                "reviewer": "Test",
                "cve_only": True,
            }
        }

    def test_docx_and_pdf_use_target_name_without_timestamp(self):
        package = Package("foo", "1.0", "1")
        package.add_license("MIT")

        doc, _, _ = repo_docx.generate_docx_report(
            self.target_name,
            "2026-10-22",
            "2026-10-22",
            [package],
            [],
            None,
            self._config(),
        )
        save_docx_report(doc, self.paths["docx_report"])

        self.assertTrue(os.path.isfile(self.paths["docx_report"]))
        self.assertEqual(
            os.path.basename(self.paths["docx_report"]),
            f"{self.target_name} 安全引入评估报告.docx",
        )
        self.assertIsNone(
            re.search(r"\d{14}", os.path.basename(self.paths["docx_report"])))

        pdf_path = convert_docx_to_pdf(
            self.paths["docx_report"], self.paths["output_dir"])
        self.assertTrue(os.path.isfile(pdf_path))
        self.assertEqual(
            os.path.basename(pdf_path),
            f"{self.target_name} 安全引入评估报告.pdf",
        )

    def test_docx_title_and_header_contain_target_name(self):
        package = Package("foo", "1.0", "1")
        package.add_license("MIT")

        doc, _, _ = repo_docx.generate_docx_report(
            self.target_name,
            "2026-10-22",
            "2026-10-22",
            [package],
            [],
            None,
            self._config(),
        )
        save_docx_report(doc, self.paths["docx_report"])

        with zipfile.ZipFile(self.paths["docx_report"]) as archive:
            document_xml = archive.read("word/document.xml").decode("utf-8")
            header_xml = "".join(
                archive.read(name).decode("utf-8")
                for name in archive.namelist()
                if name.startswith("word/header")
            )

        self.assertIn(self.target_name, document_xml)
        self.assertIn(self.target_name, header_xml)
        self.assertNotIn("@TARGET", document_xml)
        self.assertNotIn("@TARGET", header_xml)


if __name__ == "__main__":
    unittest.main()
