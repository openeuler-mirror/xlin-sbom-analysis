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

from actions.reporter.reporter_toolkit import analyze_licenses
from actions.license_helper import LICENSE_CATEGORY_DETAILS


def _generate_dep_license_section_docx():
    """
    生成许可证分析部分的DOCX内容
    """


def _generate_license_section_docx(doc, license_summary):
    """
    生成许可证分析部分的DOCX内容

    Args:
        doc (Document): python-docx文档对象，用于添加内容
        license_summary (dict): 许可证摘要信息，包含许可证类型及其出现次数

    Returns:
        None: 该函数直接修改传入的doc对象，不返回任何值
    """

    if not license_summary:
        doc.add_paragraph("未发现许可证信息。")
        return

    # 创建从scancode_category到详细信息的映射
    category_to_detail = {item["scancode_category"]
        : item for item in LICENSE_CATEGORY_DETAILS}

    analysis = analyze_licenses(license_summary)
    doc.add_paragraph(f"该软件包包含：")

    # 生成类别统计
    for category, count in analysis["category_counts"].items():
        if category in category_to_detail:
            desc = category_to_detail[category]["description"]
            doc.add_paragraph(f"{count}种{desc}", style='圆点')

    # 输出非零类别的具体许可证
    for category, licenses_set in analysis["category_licenses"].items():
        if licenses_set and category != "Unknown":
            doc.add_paragraph(f"其中{category}的许可证如下：")
            for lic in sorted(licenses_set):
                doc.add_paragraph(f"{lic}", style='圆点')

            # 添加suggestion内容
            suggestion = category_to_detail[category]["suggestion"]
            doc.add_paragraph(f"{suggestion}")
            doc.add_paragraph()

    doc.add_paragraph()


def _generate_dep_vulnerability_table_docx(doc, packages):
    """
    生成漏洞信息表格并添加到DOCX文档中

    Args:
        doc (Document): python-docx文档对象，用于添加表格内容
        packages (list): 软件包列表，每个元素为包含漏洞信息的Package对象

    Returns:
        None: 该函数直接修改传入的doc对象，不返回任何值
    """

    # 创建表格
    table = doc.add_table(rows=1, cols=6)
    table.style = 'Table Grid'

    # 添加表头
    hdr_cells = table.rows[0].cells
    hdr_cells[0].text = '依赖项名'
    hdr_cells[1].text = '版本'
    hdr_cells[2].text = '漏洞ID'
    hdr_cells[3].text = '漏洞评分标准'
    hdr_cells[4].text = '漏洞评分'
    hdr_cells[5].text = '修复版本'

    # 应用表头样式
    for cell in hdr_cells:
        for paragraph in cell.paragraphs:
            paragraph.style = '表格标题'

    # 填充表格数据
    for package in packages:
        for vuln in package.vulnerabilities:
            row_cells = table.add_row().cells
            row_cells[0].text = package.name
            row_cells[1].text = f"{package.version}"
            row_cells[2].text = vuln['id']
            row_cells[3].text = vuln.get('severity_type', 'N/A')
            row_cells[4].text = vuln.get('severity_level', 'N/A')
            row_cells[5].text = vuln.get('fixed', 'N/A')

            # 应用表格内容样式
            for cell in row_cells:
                for paragraph in cell.paragraphs:
                    paragraph.style = '表格内容'

    doc.add_paragraph()


def _generate_vulnerability_table_docx(doc, package):
    """
    生成软件包漏洞信息表格并添加到DOCX文档中

    Args:
        doc (Document): python-docx文档对象，用于添加表格内容
        package (Package): 包含漏洞信息的Package对象

    Returns:
        None: 该函数直接修改传入的doc对象，不返回任何值
    """

    # 创建表格
    table = doc.add_table(rows=1, cols=4)
    table.style = 'Table Grid'

    # 添加表头
    hdr_cells = table.rows[0].cells
    hdr_cells[0].text = '漏洞ID'
    hdr_cells[1].text = '漏洞评分标准'
    hdr_cells[2].text = '漏洞评分'
    hdr_cells[3].text = '修复版本'

    # 应用表头样式
    for cell in hdr_cells:
        for paragraph in cell.paragraphs:
            paragraph.style = '表格标题'

    # 填充表格数据
    for vuln in package.vulnerabilities:
        row_cells = table.add_row().cells
        row_cells[0].text = vuln['id']
        row_cells[1].text = vuln.get('severity_type', 'N/A')
        row_cells[2].text = vuln.get('severity_level', 'N/A')
        row_cells[3].text = vuln.get('fixed', 'N/A')

        # 应用表格内容样式
        for cell in row_cells:
            for paragraph in cell.paragraphs:
                paragraph.style = '表格内容'

    doc.add_paragraph()


def generate_docx_report():
    """
    生成DOCX格式的扫描报告
    """
