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


import packaging.version

class VersionComparator:
    """版本比较辅助类，用于处理复杂的版本范围逻辑"""
    @staticmethod
    def _to_comparable(v_str):
        if v_str == "0":
            return packaging.version.parse("0.0.0"), True
        
        clean_v = v_str.lstrip('v').split('+')[0]
        try:
            return packaging.version.parse(clean_v), True
        except:
            # 解析失败则进行简单标准化处理
            return clean_v.replace('-', '.'), False

    @classmethod
    def compare(cls, v1_str, v2_str):
        """安全的比较函数：v1 >= v2"""
        val1, is_obj1 = cls._to_comparable(v1_str)
        val2, is_obj2 = cls._to_comparable(v2_str)

        if is_obj1 and is_obj2:
            return val1 >= val2
        return str(val1) >= str(val2)

    @classmethod
    def is_in_range(cls, current_v, events):
        affected = False
        for event in events:
            if 'introduced' in event:
                if cls.compare(current_v, event['introduced']):
                    affected = True
            elif 'fixed' in event:
                if cls.compare(current_v, event['fixed']):
                    affected = False
            elif 'last_affected' in event:
                if not cls.compare(event['last_affected'], current_v):
                    affected = False
        return affected
