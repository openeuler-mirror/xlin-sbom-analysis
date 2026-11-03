# Copyright (c) 2025 Linx Software, Inc.
#
# xlin-sbom-analysis tool is licensed under Mulan PSL v2.

# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
# http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

"""扫描报告目录与文件命名的统一变量定义。"""

DATA_DIR_NAME = "分析记录"

REPORT_NAME = "安全引入评估报告"
LICENSE_PIE_CHART_NAME = "许可证分布图"
DEP_SCAN_RESULTS_NAME = "依赖项扫描结果"
FILES_INFO_NAME = "文件级许可证信息"
DEP_LICENSE_PIE_CHART_NAME = "依赖项许可证分布图"
VULN_RESULTS_NAME = "漏洞扫描结果"

DOCX_EXT = "docx"
PDF_EXT = "pdf"
PNG_EXT = "png"
JSON_EXT = "json"

OUTPUT_DIR_TEMPLATE = "{base_name}_{timestamp}"
FILE_NAME_TEMPLATE = "{file_basename} {title}.{ext}"
TARGET_NAME_TEMPLATE = "{distro_name}-{modified_date}"
PACKAGE_NAME_TEMPLATE = "{name}-{version}"

RUN_TIMESTAMP_FORMAT = "%Y%m%d%H%M%S"
DATE_FORMAT = "%Y-%m-%d"
COMPACT_DATE_FORMAT = "%Y%m%d"
DATE_SEPARATOR = "-"

UPDATE_SEGMENT = "update"
SOURCE_SEGMENT = "source"
UPDATE_SOURCE_PATH = f"{UPDATE_SEGMENT}/{SOURCE_SEGMENT}"
REPOMD_FILE_NAME = "repomd.xml"
REPOMD_RELATIVE_PATH = f"repodata/{REPOMD_FILE_NAME}"
PRIMARY_XML_NAME = "primary.xml"
PRIMARY_XML_SUFFIXES = (".gz", ".zst")
UNKNOWN_NAME = "unknown"


def build_output_dir_name(base_name, timestamp):
    """生成结果文件夹名称。"""

    return OUTPUT_DIR_TEMPLATE.format(
        base_name=base_name, timestamp=timestamp)


def build_file_name(file_basename, title, ext):
    """生成文件夹内文件名称。"""

    return FILE_NAME_TEMPLATE.format(
        file_basename=file_basename, title=title, ext=ext)


def build_target_name(distro_name, modified_date):
    """生成报告扫描对象名称。"""

    compact_date = modified_date.replace(DATE_SEPARATOR, "")
    return TARGET_NAME_TEMPLATE.format(
        distro_name=distro_name, modified_date=compact_date)


def build_package_name(name, version):
    """生成软件包名称。"""

    return PACKAGE_NAME_TEMPLATE.format(name=name, version=version)
