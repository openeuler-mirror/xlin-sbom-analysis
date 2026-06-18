# Copyright (c) 2026 Linx Software, Inc.
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
import orjson
import os
from actions.local.osv_db import OSVdb
from actions.data_helper import read_data_from_json
from actions import ASSIST_DIR

def main():
    parser = argparse.ArgumentParser(description="OSV 漏洞数据库管理工具 (ES 版)")

    subparsers = parser.add_subparsers(dest="command", help="可用命令")

    # Ingest 子命令
    ingest_parser = subparsers.add_parser("ingest", help="将 OSV JSON 数据导入 ES")
    ingest_parser.add_argument("-d", "--dir", required=True, help="包含 JSON 文件的源目录路径")

    # Query 子命令
    query_parser = subparsers.add_parser("query", help="查询漏洞")
    query_parser.add_argument("-e", "--ecosystem", required=True, help="生态系统 (例: Debian:12)")
    query_parser.add_argument("-p", "--package", required=True, help="包名")
    query_parser.add_argument("-v", "--version", required=True, help="当前安装的版本号")

    # Delete 子命令
    subparsers.add_parser("delete", help="删除索引并释放空间")

    # Get 子命令 (新加入)
    get_parser = subparsers.add_parser("get", help="通过漏洞 ID 获取完整数据")
    get_parser.add_argument("id", help="漏洞 ID (例如: GHSA-7f3p-27pv-mjpx 或 CVE-2023-xxxx)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return
    
    # 初始化管理器
    default_config_path = os.path.join(ASSIST_DIR, 'config.json')
    try:
        CONFIG = read_data_from_json(default_config_path).get("elastic_search")
    except Exception as e:
        print(f"无法读取默认配置文件: {e}")
        return

    osv_db = OSVdb(**CONFIG)

    try:
        if args.command == "ingest":
            osv_db.ingest_from_dir(args.dir)
        
        elif args.command == "query":
            results = osv_db.query_vulnerability(args.ecosystem, args.package, args.version)
            # 使用 orjson 快速序列化并输出到终端
            print(orjson.dumps(results, option=orjson.OPT_INDENT_2).decode())

        elif args.command == "get":
            # 调用新功能：获取单条漏洞详情
            detail = osv_db.get_by_id(args.id)
            print(orjson.dumps(detail, option=orjson.OPT_INDENT_2).decode())

        elif args.command == "delete":
            confirm = input(f"确定要删除索引 '{osv_db.index_name}' 吗？此操作不可恢复！(y/n): ")
            if confirm.lower() == 'y':
                osv_db.delete_index()
            else:
                print("操作取消。")
                
    except Exception as e:
        print(f"运行时出错: {e}")

if __name__ == "__main__":
    main()