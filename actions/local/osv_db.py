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


import os
import glob
import json
import orjson
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm
from elasticsearch import Elasticsearch, helpers, exceptions
from actions.local.version_comparator import VersionComparator


class OSVdb:
    def __init__(self, hosts, index_name, api_key):
        """
        初始化 ES 客户端，集成了数据导入和查询功能
        """
        self.es = Elasticsearch(hosts, api_key=api_key)
        self.index_name = index_name

    # --- 索引维护与数据导入部分 ---
    def get_mapping(self):
        """获取索引映射定义"""
        return {
            "mappings": {
                "dynamic": "true",
                "properties": {
                    "id": {"type": "keyword"},
                    "modified": {"type": "date"},
                    "published": {"type": "date"},
                    "withdrawn": {"type": "date"},
                    "aliases": {"type": "keyword", "index": False},
                    "upstream": {"type": "keyword", "index": False},
                    "related": {"type": "keyword", "index": False},
                    "summary": {"type": "text"},
                    "details": {"type": "text"},
                    "severity": {"type": "object"},
                    "affected": {
                        "type": "nested",
                        "properties": {
                            "package": {
                                "properties": {
                                    "ecosystem": {"type": "keyword"},
                                    "name": {"type": "keyword"},
                                    "purl": {"type": "keyword"},
                                }
                            },
                            "ranges": {"type": "object", "enabled": False},
                            "versions": {"type": "keyword"},
                            "ecosystem_specific": {"type": "object", "enabled": False},
                            "database_specific": {"type": "object", "enabled": False},
                        },
                    },
                    "references": {"type": "object", "enabled": False},
                    "credits": {"type": "object", "enabled": False},
                    "database_specific": {"type": "object", "enabled": False},
                },
            }
        }

    def create_index(self):
        """创建索引（如果不存在）"""
        if not self.es.indices.exists(index=self.index_name):
            self.es.indices.create(index=self.index_name, body=self.get_mapping())

    def delete_index(self):
        if self.es.indices.exists(index=self.index_name):
            self.es.indices.delete(index=self.index_name, ignore_unavailable=True)
            print(f"[*] 索引 '{self.index_name}' 已成功删除。")
        else:
            print(f"[!] 索引 '{self.index_name}' 不存在，无需删除。")

    @staticmethod
    def _read_single_json(file_path):
        """静态方法：用于多进程读取文件"""
        try:
            with open(file_path, "rb") as f:
                return orjson.loads(f.read())
        except Exception:
            return None

    def _generate_actions(self, data_batch):
        """批量操作生成器"""
        for data in data_batch:
            if data:
                yield {
                    "_index": self.index_name,
                    "_id": data.get("id"),
                    "_source": data,
                }

    def ingest_from_dir(self, dir_path, batch_size=5000):
        """
        从目录快速导入 OSV 数据
        """
        search_pattern = os.path.join(dir_path, "**", "*.json")
        json_files = glob.glob(search_pattern, recursive=True)

        total_files = len(json_files)
        if total_files == 0:
            print(f"[-] 未在 {dir_path} 发现 JSON 文件。")
            return

        print(f"[+] 发现 {total_files} 个文件，开始导入...")
        self.create_index()
        pbar = tqdm(total=total_files, desc="Ingesting OSV Data", unit="file")

        with ProcessPoolExecutor() as executor:
            for i in range(0, total_files, batch_size):
                chunk_files = json_files[i : i + batch_size]
                futures = [
                    executor.submit(self._read_single_json, f) for f in chunk_files
                ]

                batch_data = []
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        batch_data.append(result)
                    pbar.update(1)

                if batch_data:
                    try:
                        success, errors = helpers.bulk(
                            self.es,
                            self._generate_actions(batch_data),
                            raise_on_error=False,
                        )
                        if errors:
                            with open("ingest_errors.log", "a", encoding="utf-8") as f:
                                for error_item in errors:
                                    f.write(json.dumps(error_item) + "\n")
                    except Exception as e:
                        print(f"\n[!] 批量写入异常: {e}")

        pbar.close()
        print("[+] 导入任务完成。")

    # --- 查询部分 ---
    def _extract_fixed_version(self, affected_item):
        """提取修复版本"""
        for r in affected_item.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
        return "N/A"

    def query_vulnerability(self, ecosystem, package_name, version):
        """
        查询特定生态、包名和版本的漏洞
        """
        query = {
            "query": {
                "nested": {
                    "path": "affected",
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"affected.package.ecosystem": ecosystem}},
                                {"term": {"affected.package.name": package_name}},
                            ],
                            "should": [
                                # 如果 versions 数组里直接包含这个字符串，优先匹配
                                {"term": {"affected.versions": version}}
                            ],
                        }
                    },
                }
            }
        }

        hits = helpers.scan(self.es, query=query, index=self.index_name)
        results = []

        for hit in hits:
            source = hit["_source"]
            for affected_item in source.get("affected", []):
                pkg = affected_item.get("package", {})
                if (
                    pkg.get("ecosystem") == ecosystem
                    and pkg.get("name") == package_name
                ):
                    is_hit = False
                    # 1. 匹配确切版本列表
                    if version in affected_item.get("versions", []):
                        is_hit = True

                    # 2. 匹配范围逻辑
                    if not is_hit:
                        for r in affected_item.get("ranges", []):
                            if VersionComparator.is_in_range(
                                version, r.get("events", [])
                            ):
                                is_hit = True
                                break

                    if is_hit:
                        vuln_info = {
                            "id": source.get("id"),
                            "modified": source.get("modified"),
                            "published": source.get("published"),
                            "withdrawn": source.get("withdrawn"),
                            "aliases": source.get("aliases", []),
                            "upstream": source.get("upstream", []),
                            "related": source.get("related", []),
                            "summary": source.get("summary"),
                            "details": source.get("details"),
                            "severity": source.get("severity", []),
                            "references": source.get("references", []),
                            "credits": source.get("credits", []),
                            "database_specific": source.get("database_specific"),
                            "fixed": self._extract_fixed_version(affected_item),
                        }
                        results.append(vuln_info)
                        break
        return results

    def get_by_id(self, vuln_id):
        """直接通过漏洞 ID 获取完整原始数据"""
        try:
            res = self.es.get(index=self.index_name, id=vuln_id)
            return res["_source"]
        except exceptions.NotFoundError:
            return {"error": f"漏洞 ID '{vuln_id}' 未在数据库中找到。"}
        except Exception as e:
            return {"error": str(e)}
