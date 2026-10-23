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


import gzip
import zstandard as zstd
import logging
import os
import tempfile
import xml.etree.ElementTree as ET
import datetime
from urllib.parse import unquote, urlsplit
from typing import List, Tuple
from actions import naming
from actions.package import Package
from actions.license_helper import (
    split_license,
    get_license_category,
    filter_licenses,
    count_licenses,
    licenses_visualization,
)
from actions.scanner.vulnerability_helper import (
    query_osv_vulnerability,
    process_osv_vuln
)
from actions.data_helper import (
    save_data_to_json,
    save_docx_report,
    convert_docx_to_pdf,
    download_file,
    setup_paths,
    get_scan_dates,
    log_scan_summary)
import actions.reporter.docx_reporter_repo as repo_docx
from tqdm import tqdm

def _scan_primary_xml(file_path: str, data_dir: str, disable_tqdm: bool, config) -> Tuple[List[str], List[Package]]:
    """
    扫描并解析primary.xml压缩文件，提取软件包信息、许可证和漏洞数据

    Args:
        file_path (str): primary.xml压缩文件的路径
        data_dir (str): 用于保存漏洞扫描结果数据的目录路径
        disable_tqdm (bool): 是否禁用tqdm进度条显示
        config (dict): 配置对象，包含配置参数，如是否只处理CVE漏洞等

    Returns:
        Tuple[List[Package], List[dict]]: 包含两个元素的元组
            - packages (List[Package]): 成功处理的软件包列表，每个元素为Package对象
            - failed_packages (List[dict]): 处理失败的软件包信息列表，每个元素为包含name、version、release和error字段的字典
    """

    if file_path.endswith('.gz'):
        # 处理gzip格式
        with gzip.open(file_path, 'rb') as f:
            tree = ET.parse(f)
            root = tree.getroot()
    elif file_path.endswith('.zst'):
        # 处理zstd格式
        with open(file_path, 'rb') as f:
            dctx = zstd.ZstdDecompressor()
            with dctx.stream_reader(f) as reader:
                tree = ET.parse(reader)
                root = tree.getroot()
    else:
        raise ValueError(f"不支持的文件格式: {file_path}。仅支持 .gz 和 .zst 格式")

    # 定义XML命名空间
    ns = {
        'common': 'http://linux.duke.edu/metadata/common',
        'rpm': 'http://linux.duke.edu/metadata/rpm'
    }

    packages = []
    failed_packages = []  # 存储处理失败的包信息

    # 获取所有package元素并添加进度条
    pkg_elems = root.findall('common:package', ns)
    for pkg_elem in tqdm(pkg_elems, desc="Processing packages", disable=disable_tqdm):
        try:
            # 提取基本信息
            name = pkg_elem.find('common:name', ns).text
            version_elem = pkg_elem.find('common:version', ns)
            ver = version_elem.get('ver')
            rel = version_elem.get('rel')

            # 创建Package对象
            pkg = Package(name, ver, rel)

            logging.debug(f"Package identified：{name}-{ver}.{rel}")

            # 提取许可证信息
            format_elem = pkg_elem.find('common:format', ns)
            license_elem = format_elem.find('rpm:license', ns)
            license_text = license_elem.text if license_elem is not None else ""
            pkg.add_license(license_text)

            # 添加许可证类别
            license_list = split_license(license_text)
            for license_name in license_list:
                category = get_license_category(license_name)
                if category and category != "Unknown":
                    pkg.add_category(category)

            # 处理漏洞信息 - 如果查询失败则不添加该包
            osv_vulnerability = query_osv_vulnerability(name, ver, config)
            if osv_vulnerability:
                vulns_record = os.path.join(
                    data_dir,
                    naming.build_file_name(
                        f"{name}-{ver}.{rel}",
                        naming.VULN_RESULTS_NAME,
                        naming.JSON_EXT))
                save_data_to_json(osv_vulnerability, vulns_record)

            vulns = osv_vulnerability.get("vulns", [])
            for vuln in vulns:
                vuln_id, severity_type, severity_level, fixed = process_osv_vuln(
                    vuln, name)
                if not config.get('general', {}).get('cve_only') or vuln_id.startswith("CVE"):
                    pkg.add_vulnerability(
                        vuln_id, severity_type, severity_level, fixed)

            packages.append(pkg)

        except Exception as e:
            # 记录处理失败的包信息
            failed_packages.append({
                "name": name,
                "version": ver,
                "release": rel,
                "error": str(e)
            })
            logging.debug(str(e))

    return packages, failed_packages



def _scan_repomd(repomd_path, update_source_url):
    """
    扫描并解析repomd.xml文件，提取primary数据的URL和时间戳

    Args:
        repomd_path (str): repomd.xml文件的本地路径
        update_source_url (str): update/source目录的完整URL地址

    Returns:
        tuple: 包含两个元素的元组：
               - primary_url (str): primary.xml.gz文件的完整URL地址，如果解析失败则为None
               - formatted_date (str): 格式化后的时间戳日期(YYYY-MM-DD)，如果解析失败则为None
    """

    try:
        # 解析XML文件
        tree = ET.parse(repomd_path)
        root = tree.getroot()

        # 定义XML命名空间
        namespace = {'repo': 'http://linux.duke.edu/metadata/repo'}

        # 查找type为primary的data元素
        primary_data = root.find(".//repo:data[@type='primary']", namespace)
        if primary_data is None:
            logging.error("在repomd.xml中未找到primary数据")
            return None, None

        # 提取location元素的href属性
        location = primary_data.find("repo:location", namespace)
        if location is None:
            logging.error("在primary数据中未找到location信息")
            return None, None

        href = location.get("href")
        if not href:
            logging.error("location元素中没有href属性")
            return None, None

        # 提取timestamp
        timestamp_elem = primary_data.find("repo:timestamp", namespace)
        if timestamp_elem is None:
            logging.error("在primary数据中未找到timestamp信息")
            return None, None

        timestamp_str = timestamp_elem.text
        if not timestamp_str:
            logging.error("timestamp元素中没有内容")
            return None, None

        # 将时间戳转换为日期格式
        try:
            timestamp_int = int(timestamp_str)
            formatted_date = datetime.datetime.fromtimestamp(
                timestamp_int).strftime(naming.DATE_FORMAT)
        except ValueError:
            logging.error(f"时间戳格式无效: {timestamp_str}")
            return None, None

        # 拼接完整的URL
        primary_url = f"{update_source_url}/{href.lstrip('/')}"
        return primary_url, formatted_date  # 返回格式化后的日期

    except ET.ParseError as e:
        logging.error(f"解析repomd.xml失败: {e}")
        return None, None
    except Exception as e:
        logging.error(f"处理repomd.xml时发生未知错误: {e}")
        return None, None



def _extract_primary_xml(text):
    """
    从给定的URL字符串中中提取primary.xml及其后续内容

    Args:
        text (str): 输入的文本字符串，通常是从URL中提取的部分路径

    Returns:
        str: 如果输入文本包含"primary.xml"，则返回从"primary.xml"开始的子字符串；
             如果不包含，则返回原始输入文本
    """

    before, separator, after = text.partition(naming.PRIMARY_XML_NAME)
    if separator:
        return naming.PRIMARY_XML_NAME + after
    return text

def _get_update_source_url(repo_url):
    """
    获取仓库的 update/source 目录地址。

    支持传入仓库根地址或已经包含 update/source 的地址，避免重复拼接。

    Args:
        repo_url (str): 仓库根地址或 update/source 地址

    Returns:
        str: update/source 目录地址
    """

    suffix = f"/{naming.UPDATE_SOURCE_PATH}"
    base_url = repo_url.rstrip('/')
    if base_url.endswith(suffix):
        return base_url
    return f"{base_url}{suffix}"


def _extract_distro_name(repo_url):
    """
    从仓库地址中提取发行版名称。

    优先取 "/update/" 前一段路径作为发行版名称，例如
    "https://.../openEuler-24.03-LTS-SP1/update/source/" 返回
    "openEuler-24.03-LTS-SP1"；无法识别时回退为路径最后一段。

    Args:
        repo_url (str): 仓库地址或 primary.xml 地址

    Returns:
        str: 发行版名称
    """

    path = unquote(urlsplit(repo_url).path)
    parts = [part for part in path.split('/') if part]

    for index, part in enumerate(parts):
        if part.lower() == naming.UPDATE_SEGMENT and index > 0:
            return parts[index - 1]

    if parts:
        return parts[-1]

    fallback = os.path.basename(repo_url.rstrip('/'))
    return fallback or naming.UNKNOWN_NAME


def _format_target_name(distro_name, modified_date):
    """
    生成报告使用的扫描对象名称。

    Args:
        distro_name (str): 发行版名称
        modified_date (str): 仓库修改日期，支持 "YYYY-MM-DD" 或 "YYYYMMDD"

    Returns:
        str: 形如 "openEuler-24.03-LTS-SP1-20261022" 的名称
    """

    return naming.build_target_name(distro_name, modified_date)


def scan_repo(args, formatted_utc_time, config):
    """
    扫描单个源代码仓库，生成安全引入评估报告。

    Args:
        args (argparse.Namespace): 命令行参数对象，包含repo、output、disable_tqdm等属性
        formatted_utc_time (str): 格式化的时间字符串，用于生成唯一的文件名
        config (dict): 配置字典，包含扫描和报告生成的相关配置

    Returns:
        None: 该函数不返回任何值，直接生成报告文件并记录日志
    """

    base_repo_url = args.repo.rstrip('/')
    repo_name = _extract_distro_name(base_repo_url)

    with tempfile.TemporaryDirectory() as temp_dir:
        if base_repo_url.endswith(naming.PRIMARY_XML_SUFFIXES):
            # 指定扫描
            primary_xml_path = os.path.join(
                temp_dir, _extract_primary_xml(base_repo_url))
            modified_date = datetime.date.today().strftime(
                naming.COMPACT_DATE_FORMAT)

            if not download_file(base_repo_url, primary_xml_path):
                logging.error(f"从 {base_repo_url} 下载 primary.xml 时出错。")
                return
        else:
            # 自动探测
            update_source_url = _get_update_source_url(base_repo_url)
            repomd_url = (
                f"{update_source_url}/{naming.REPOMD_RELATIVE_PATH}")
            logging.info(f"正在从 {repomd_url} 获取最新软件包信息...")

            repomd_path = os.path.join(temp_dir, naming.REPOMD_FILE_NAME)
            if not download_file(repomd_url, repomd_path):
                logging.error(f"无法从 {base_repo_url} 获取数据，请检查网络连接或仓库地址。")
                return

            primary_url, repomd_date = _scan_repomd(
                repomd_path, update_source_url)
            if not primary_url or not repomd_date:
                logging.error(f"无法解析 {repomd_url} 中的 primary 数据。")
                return

            primary_xml_path = os.path.join(
                temp_dir, _extract_primary_xml(primary_url))
            modified_date = repomd_date.replace(naming.DATE_SEPARATOR, "")

            if not download_file(primary_url, primary_xml_path):
                logging.error(f"从 {primary_url} 下载 primary.xml 时出错。")
                return

        target_name = _format_target_name(repo_name, modified_date)
        paths = setup_paths(
            args.output, repo_name, formatted_utc_time, target_name)

        packages, failed_packages = _scan_primary_xml(
            primary_xml_path, paths['data_dir'], args.disable_tqdm, config)

        log_scan_summary(
            len(packages) + len(failed_packages), failed_packages)

        repo_licenses = [
            lic for package in packages for lic in split_license(package.license)]
        license_summary = filter_licenses(count_licenses(repo_licenses))
        if license_summary:
            licenses_visualization(
                license_summary, paths['licenses_pie_chart'])

        start_date, end_date = get_scan_dates(config)
        report, _, _ = repo_docx.generate_docx_report(
            target_name, start_date, end_date, packages,
            license_summary, paths['licenses_pie_chart'], config
        )

        save_docx_report(report, paths['docx_report'])
        try:
            convert_docx_to_pdf(paths['docx_report'], paths['output_dir'])
            logging.info(f"安全引入评估报告已保存至: {paths['output_dir']}")
        except Exception as e:
            logging.error(f"PDF 转换失败: {e}")
