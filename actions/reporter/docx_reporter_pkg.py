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

def _generate_dep_license_section_docx():
    """
    生成许可证分析部分的DOCX内容
    """

def _generate_license_section_docx():
    """
    生成许可证分析部分的DOCX内容
    """

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
