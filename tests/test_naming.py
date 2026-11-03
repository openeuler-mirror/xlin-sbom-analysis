import os
import re
import tempfile
import unittest

from actions.data_helper import setup_paths
from actions.scanner.repo_helper import (
    _extract_distro_name,
    _format_target_name,
    _get_update_source_url,
)


class RepoNamingTests(unittest.TestCase):
    def test_extract_distro_from_source_url(self):
        url = ("https://dl-cdn.openeuler.openatom.cn/"
               "openEuler-24.03-LTS-SP1/update/source/")
        self.assertEqual(
            _extract_distro_name(url), "openEuler-24.03-LTS-SP1")

    def test_extract_distro_from_repo_root(self):
        url = ("https://dl-cdn.openeuler.openatom.cn/"
               "openEuler-24.03-LTS/")
        self.assertEqual(_extract_distro_name(url), "openEuler-24.03-LTS")

    def test_extract_distro_from_primary_xml(self):
        url = ("https://dl-cdn.openeuler.openatom.cn/"
               "openEuler-24.03-LTS/update/source/repodata/"
               "abc-primary.xml.gz")
        self.assertEqual(_extract_distro_name(url), "openEuler-24.03-LTS")

    def test_extract_distro_without_update_segment(self):
        url = "https://example.com/foo/bar/"
        self.assertEqual(_extract_distro_name(url), "bar")

    def test_extract_distro_from_local_path(self):
        self.assertEqual(_extract_distro_name("csan_code"), "csan_code")

    def test_update_source_url_from_repo_root(self):
        url = ("https://dl-cdn.openeuler.openatom.cn/"
               "openEuler-24.03-LTS-SP1/")
        self.assertEqual(
            _get_update_source_url(url),
            "https://dl-cdn.openeuler.openatom.cn/"
            "openEuler-24.03-LTS-SP1/update/source",
        )

    def test_update_source_url_is_not_duplicated(self):
        url = ("https://dl-cdn.openeuler.openatom.cn/"
               "openEuler-24.03-LTS-SP1/update/source/")
        self.assertEqual(
            _get_update_source_url(url),
            "https://dl-cdn.openeuler.openatom.cn/"
            "openEuler-24.03-LTS-SP1/update/source",
        )

    def test_format_target_name_from_full_date(self):
        self.assertEqual(
            _format_target_name("openEuler-24.03-LTS-SP1", "2026-10-22"),
            "openEuler-24.03-LTS-SP1-20261022",
        )

    def test_format_target_name_from_compact_date(self):
        self.assertEqual(
            _format_target_name("openEuler-24.03-LTS-SP1", "20261022"),
            "openEuler-24.03-LTS-SP1-20261022",
        )


class SetupPathsTests(unittest.TestCase):
    timestamp = "20261022153000"

    def setUp(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        self.output_base = self._temp_dir.name

    def tearDown(self):
        self._temp_dir.cleanup()

    def _assert_no_run_timestamp(self, path):
        self.assertIsNone(re.search(r"\d{14}", os.path.basename(path)))

    def test_repo_paths(self):
        base_name = "openEuler-24.03-LTS-SP1"
        file_basename = "openEuler-24.03-LTS-SP1-20261022"
        paths = setup_paths(
            self.output_base, base_name, self.timestamp, file_basename)

        self.assertEqual(
            os.path.basename(paths["output_dir"]),
            f"{base_name}_{self.timestamp}",
        )
        self.assertEqual(os.path.basename(paths["data_dir"]), "分析记录")
        self.assertEqual(
            os.path.basename(paths["docx_report"]),
            f"{file_basename} 安全引入评估报告.docx",
        )
        self.assertEqual(
            os.path.basename(paths["licenses_pie_chart"]),
            f"{file_basename} 许可证分布图.png",
        )
        self.assertEqual(
            os.path.basename(paths["vulns_record"]),
            f"{file_basename} 漏洞扫描结果.json",
        )

        for key, value in paths.items():
            if key in ("output_dir", "data_dir"):
                continue
            self._assert_no_run_timestamp(value)

    def test_sbom_paths_use_base_name_for_files(self):
        base_name = "minimal-sbom"
        paths = setup_paths(self.output_base, base_name, self.timestamp)

        self.assertEqual(
            os.path.basename(paths["output_dir"]),
            f"{base_name}_{self.timestamp}",
        )
        self.assertEqual(
            os.path.basename(paths["docx_report"]),
            f"{base_name} 安全引入评估报告.docx",
        )
        self._assert_no_run_timestamp(paths["docx_report"])

    def test_batch_paths_use_package_name_for_files(self):
        base_name = "urllib3-1.26.4"
        paths = setup_paths(self.output_base, base_name, self.timestamp)

        self.assertEqual(
            os.path.basename(paths["output_dir"]),
            f"{base_name}_{self.timestamp}",
        )
        self.assertEqual(
            os.path.basename(paths["docx_report"]),
            f"{base_name} 安全引入评估报告.docx",
        )
        self._assert_no_run_timestamp(paths["docx_report"])

    def test_output_directory_contains_timestamp(self):
        paths = setup_paths(
            self.output_base, "openEuler-24.03-LTS-SP1", self.timestamp)
        self.assertRegex(
            os.path.basename(paths["output_dir"]), r"\d{14}$")


if __name__ == "__main__":
    unittest.main()
