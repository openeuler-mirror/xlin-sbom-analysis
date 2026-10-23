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

import argparse
import os
import logging
import time
from actions.scanner.repo_helper import scan_repo
from actions.scanner.sbom_helper import scan_sbom
from actions.data_helper import read_data_from_json
from actions import LOG_DIR, ASSIST_DIR, naming


def _parse_arguments():
    """
    解析命令行参数

    Args:
        None: 该函数不接受任何参数，直接从命令行获取参数

    Returns:
        argparse.Namespace: 包含解析后的命令行参数的对象，包含以下属性：
            - sbom (str): 待扫描的SBOM文件路径
            - output (str): 安全评估报告输出目录
            - disable_tqdm (bool): 是否禁用进度条显示
            - config (str): 外部配置文件路径
    """

    parser = argparse.ArgumentParser(
        description='对SBOM文件进行安全评估，并生成安全评估报告。')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--repo", "-r", help="待扫描的源代码仓库地址。")
    group.add_argument("--sbom", "-s", help="SBOM文件路径")

    parser.add_argument("--output", "-o", required=True, help="安全评估报告输出目录。")
    parser.add_argument("--disable-tqdm", action='store_true', help="禁用进度条显示。")
    parser.add_argument("--config", required=False, help="外部配置文件路径。")

    return parser.parse_args()


def _setup_logging(formatted_utc_time):
    """
    配置日志记录，创建日志文件并设置日志格式和处理器，同时限制日志文件数量。

    Args:
        formatted_utc_time (str): 格式化的时间字符串，用于生成唯一的日志文件名

    Returns:
        None: 该函数不返回任何值，直接配置全局日志记录器
    """

    os.makedirs(LOG_DIR, exist_ok=True)
    log_files = sorted([os.path.join(LOG_DIR, f) for f in os.listdir(LOG_DIR) if f.startswith(
        'log_') and f.endswith('.log')], key=os.path.getctime)

    max_log_files = 200
    while len(log_files) >= max_log_files:
        file_to_delete = log_files.pop(0)
        try:
            os.remove(file_to_delete)
            logging.debug(f"删除旧日志: {file_to_delete}")
        except Exception as e:
            logging.error(f"删除 {file_to_delete} 时失败: {str(e)}")

    log_file = os.path.join(LOG_DIR, f'log_{formatted_utc_time}.log')
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    file_handler = logging.FileHandler(log_file, mode='w')
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] [%(name)s] %(message)s')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)


def _merge_configs(default_config, external_config, path=""):
    """
    合并默认配置和外部配置文件，优先使用外部配置项。

    Args:
        default_config (dict): 默认配置字典，作为基础配置
        external_config (dict): 外部配置字典，优先级高于默认配置
        path (str): 配置项的路径前缀，用于构建完整的配置项路径，主要用于日志输出

    Returns:
        dict: 合并后的配置字典，外部配置项会覆盖默认配置中的同名项
    """

    merged = default_config.copy()

    for key, external_value in external_config.items():
        # 构建当前配置项的路径，用于日志输出
        current_path = f"{path}.{key}" if path else key

        if key in merged:
            default_value = merged[key]

            if isinstance(default_value, dict) and isinstance(external_value, dict):
                merged[key] = _merge_configs(
                    default_value, external_value, path=current_path)

            # 检查类型是否匹配
            elif type(default_value) is not type(external_value):
                logging.warning(
                    f"类型不匹配: 配置项 '{current_path}'。 "
                    f"默认类型为 {type(default_value).__name__}, "
                    f"外部类型为 {type(external_value).__name__}。 "
                    "将忽略此外部配置。"
                )
                continue

            else:
                merged[key] = external_value

        else:
            merged[key] = external_value

    return merged


def main():
    """
    主函数，程序入口点。负责解析命令行参数、加载配置、初始化日志系统，
    并根据参数决定执行单个仓库扫描或批量扫描。

    Args:
        None: 该函数不接受任何参数，所有输入均来自命令行参数和配置文件

    Returns:
        None: 该函数不返回任何值，直接执行扫描任务或记录错误信息
    """

    timestamp = time.time()
    utc_time_tuple = time.gmtime(timestamp)
    formatted_utc_time = time.strftime(
        naming.RUN_TIMESTAMP_FORMAT, utc_time_tuple)

    _setup_logging(formatted_utc_time)
    args = _parse_arguments()
    logging.debug(f"命令行参数: {args}")

    default_config_path = os.path.join(ASSIST_DIR, 'config.json')
    try:
        config = read_data_from_json(default_config_path)
    except Exception as e:
        logging.error(f"无法读取默认配置文件: {e}")
        return

    if args.config:
        try:
            external_config = read_data_from_json(args.config)
            config = _merge_configs(config, external_config)
            logging.info(f"已成功加载外部配置文件: {args.config}")
        except Exception as e:
            logging.warning(
                f"无法读取外部配置文件 '{args.config}' ({e})，将使用默认配置。")

    if args.repo:
        scan_repo(args, formatted_utc_time, config)
    elif args.sbom:
        scan_sbom(args, formatted_utc_time, config)


if __name__ == '__main__':
    main()
