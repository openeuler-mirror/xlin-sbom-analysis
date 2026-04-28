# 析灵SBOM分析工具用户手册

## 概述

析灵SBOM分析工具是一个基于 Docker 容器的自动化安全引入分析工具，用于对源代码仓库、批量源码包或 SBOM 文件进行安全评估并生成详细的报告文档。本手册将指导您如何构建镜像并执行安全扫描。

## 系统要求

- **Docker**: 版本 18.09.1 或更高
- **磁盘空间**: 至少 3GB 可用空间
- **内存**: 建议 4GB 或以上
- **网络**: 需要访问外部软件仓库和漏洞数据库

## 镜像加载

如果您获得了离线镜像文件，请按以下步骤加载：

1. 获取 `xiling-analyzer-latest.tar` 镜像文件
2. 打开终端，切换到包含镜像文件的目录
3. 执行以下命令加载镜像：

```bash
docker load -i xiling-analyzer-latest.tar
```

4. 验证镜像是否加载成功：

```bash
docker images | grep xiling-analyzer
```

## 使用指南

### 扫描模式概览

根据您的需求，选择以下三种模式之一：

| 模式         | 命令参数         | 输入来源           | 典型应用场景               |
| ------------ | ---------------- | ------------------ | -------------------------- |
| 单个仓库扫描 | `--repo` / `-r`  | 在线仓库URL        | 扫描特定发行版的软件包     |
| 批量扫描     | `--batch` / `-b` | 本地CSV文件        | 批量扫描多个指定源代码项目 |
| SBOM分析     | `--sbom` / `-s`  | SBOM文件(SPDX 2.x) | 基于已有SBOM进行深入分析   |

### 基本命令结构

所有扫描模式都遵循相同的基本命令格式：

```bash
docker run --rm -v <主机输出目录>:/app/output xiling-analyzer:latest <扫描模式> --output /app/output [其他参数]
```

### 模式一：扫描单个源码仓库

此模式专为扫描在线软件仓库设计，支持两种方式：

#### 方式A：自动扫描最新软件包（推荐）

提供仓库根目录地址，工具会自动探测并扫描最新的软件包信息。

**命令格式：**
```bash
docker run --rm -v <主机输出目录>:/app/output xiling-analyzer:latest --repo <仓库根URL> --output /app/output
```

**使用示例：**
```bash
# Linux/Mac
docker run --rm -v $(pwd)/reports:/app/output xiling-analyzer:latest \
  --repo https://dl-cdn.openeuler.openatom.cn/openEuler-24.03-LTS/ \
  --output /app/output

# Windows PowerShell
docker run --rm -v ${PWD}/reports:/app/output xiling-analyzer:latest \
  --repo https://dl-cdn.openeuler.openatom.cn/openEuler-24.03-LTS/ \
  --output /app/output
```

#### 方式B：指定特定primary.xml文件

提供完整的primary.xml.gz文件地址，适用于需要扫描特定版本或历史版本的场景。

**命令格式：**
```bash
docker run --rm -v <主机输出目录>:/app/output xiling-analyzer:latest --repo <primary.xml文件URL> --output /app/output
```

**使用示例：**
```bash
# Linux/Mac
docker run --rm -v $(pwd)/reports:/app/output xiling-analyzer:latest \
  --repo https://dl-cdn.openeuler.openatom.cn/openEuler-24.03-LTS/update/source/repodata/25f85b6e3808d6cc265685aa496c2ab0772b05e964802fa68df40ec550630c29-primary.xml.gz \
  --output /app/output

# Windows PowerShell
docker run --rm -v ${PWD}/reports:/app/output xiling-analyzer:latest \
  --repo https://dl-cdn.openeuler.openatom.cn/openEuler-24.03-LTS/update/source/repodata/25f85b6e3808d6cc265685aa496c2ab0772b05e964802fa68df40ec550630c29-primary.xml.gz \
  --output /app/output
```

### 模式二：批量扫描

使用CSV文件批量定义扫描任务，适合需要对多个源代码项目进行统一评估的场景。

**命令格式：**
```bash
docker run --rm -v <主机数据目录>:/app/data -v <主机输出目录>:/app/output xiling-analyzer:latest --batch /app/data/<CSV文件名> --output /app/output
```

**CSV文件格式：**

| 字段名  | 说明               | 示例                           |
| ------- | ------------------ | ------------------------------ |
| name    | 软件包名称         | foo                            |
| version | 版本号             | 1.1.1                          |
| type    | 来源类型 (git/url) | git                            |
| path    | 仓库地址或下载链接 | https://github.com/foo/foo.git |

**示例CSV内容：**
```csv
name,version,type,path
foo,1.1.1,git,https://github.com/foo/foo.git
bar,1.0,url,https://github.com/bar/bar/archive/refs/tags/v1.0.tar.gz
baz,2.3.0,git,https://gitlab.com/baz/baz-project.git
```

**使用示例：**
```bash
# Linux/Mac
docker run --rm -v $(pwd):/app/data -v $(pwd)/reports:/app/output xiling-analyzer:latest \
  --batch /app/data/batch.csv \
  --output /app/output

# Windows PowerShell
docker run --rm -v ${PWD}:/app/data -v ${PWD}/reports:/app/output xiling-analyzer:latest \
  --batch /app/data/batch.csv \
  --output /app/output
```

### 模式三：SBOM扫描

基于已有的SBOM文件进行深入安全分析。

**命令格式：**
```bash
docker run --rm -v <主机数据目录>:/app/data -v <主机输出目录>:/app/output xiling-analyzer:latest --sbom /app/data/<SBOM文件> --output /app/output
```

**使用示例：**
```bash
# Linux/Mac
docker run --rm -v $(pwd):/app/data -v $(pwd)/reports:/app/output xiling-analyzer:latest \
  --sbom /app/data/sbom.json \
  --output /app/output

# Windows PowerShell
docker run --rm -v ${PWD}:/app/data -v ${PWD}/reports:/app/output xiling-analyzer:latest \
  --sbom /app/data/sbom.json \
  --output /app/output
```

> **注意**：当前仅支持 SPDX 2.X 格式的 SBOM 文件。

## 高级配置

### 使用配置文件

对于需要定制化扫描行为的用户，可通过JSON配置文件进行详细设置。

**配置文件示例：**
```json
{
    "general": {
        "report_version": "V1.0", 
        "date_setting": {
            "fixed_date": false,
            "date": "2025-01-01"
        },
        "author": "Alice",
        "reviewer": "Bob",
        "cve_only": true
    },
    "batch_scan": {
        "include_file_patterns": [
            "*.c", "*.h", "*.cpp", "*.hpp", "*.java", "*.py",
            "*.js", "*.ts", "*.go", "*.rs", "*.php", "*.rb",
            "*license*", "*LICENSE*", "*copyright*", "*COPYRIGHT*"
        ],
        "exclude_file_patterns": [],
        "summary_display": true
    },
    "repo_scan": {},
    "sbom_scan": {}
}
```

**关键参数说明：**

| 参数                               | 类型   | 说明                                         | 默认值             |
| ---------------------------------- | ------ | -------------------------------------------- | ------------------ |
| `general.cve_only`                 | 布尔值 | `true`: 仅显示CVE漏洞；`false`: 显示所有漏洞 | `false`            |
| `general.author`                   | 字符串 | 报告作者信息                                 | -                  |
| `general.reviewer`                 | 字符串 | 报告审核者信息                               | -                  |
| `batch_scan.include_file_patterns` | 数组   | 许可证分析包含的文件模式                     | [常见编程语言文件] |
| `batch_scan.summary_display`       | 布尔值 | 是否在控制台显示扫描总结                     | `true`             |

**使用配置文件的命令示例：**
```bash
# Linux/Mac
docker run --rm -v $(pwd)/reports:/app/output -v $(pwd)/config.json:/app/config.json xiling-analyzer:latest \
  --repo <仓库地址> \
  --output /app/output \
  --config /app/config.json

# Windows PowerShell
docker run --rm -v ${PWD}/reports:/app/output -v ${PWD}/config.json:/app/config.json xiling-analyzer:latest \
  --repo <仓库地址> \
  --output /app/output \
  --config /app/config.json
```

### 可选参数

- `--max-workers <数量>`: 设置最大并发线程数（默认：CPU核心数）
- `--disable-tqdm`: 禁用进度条显示（适用于自动化环境）
- `--config <配置文件路径>`: 指定外部配置文件路径

**使用示例：**
```bash
docker run --rm -v ./reports:/app/output xiling-analyzer:latest \
  --repo https://dl-cdn.openeuler.openatom.cn/openEuler-24.03-LTS/ \
  --output /app/output \
  --max-workers 4 \
  --disable-tqdm
```

## 输出结果

扫描完成后，报告将保存在您指定的输出目录中，包含以下文件：

| 文件/目录                        | 格式     | 说明                       |
| -------------------------------- | -------- | -------------------------- |
| `安全引入评估报告.docx`          | Word文档 | 详细的Word格式安全评估报告 |
| `安全引入评估报告.pdf`           | PDF文档  | 便于分发的PDF格式报告      |
| `分析目录/`                      | 目录     | 包含详细的扫描结果数据     |
| &nbsp;&nbsp;├── `漏洞扫描结果`   | JSON文件 | 所有组件的漏洞扫描详细结果 |
| &nbsp;&nbsp;├── `许可证扫描结果` | JSON文件 | 许可证检测和分析结果       |
| &nbsp;&nbsp;└── `许可证分布图`   | PNG图像  | 许可证分布的饼状图可视化   |

## 故障排除

### 常见问题

#### Q: 运行时出现"OpenBLAS"报错

**报错信息：**
```bash
OpenBLAS blas_thread_init: pthread_create failed for thread 1 of 12: Operation not permitted
OpenBLAS blas_thread_init: ensure that your address space and process count limits are big enough (ulimit -a)
...
```

**解决方案：**
在运行容器时添加 `--security-opt seccomp=unconfined` 参数：

```bash
docker run --rm --security-opt seccomp=unconfined -v ./reports:/app/output xiling-analyzer:latest \
  --repo <仓库地址> \
  --output /app/output
```

### 问题诊断步骤

如遇技术问题，请按以下步骤排查：

1. **检查Docker环境**
   ```bash
   docker --version
   docker info
   ```

2. **验证镜像加载**
   ```bash
   docker images | grep xiling-analyzer
   ```

3. **检查目录权限**
   - 确保挂载目录存在且有读写权限
   - 避免使用系统保护目录（如 `/root`, `/system` 等）

4. **验证输入文件格式**
   - CSV文件：检查字段分隔符和编码格式
   - SBOM文件：确认为SPDX 2.X格式

## 获取支持

如果您在使用过程中遇到问题：

1. **查看本文档**：首先确认问题是否已在文档中说明
2. **检查环境配置**：确认Docker版本、磁盘空间等符合要求
3. **收集错误信息**：记录完整的错误日志和命令行输出
4. **提供环境详情**：包括操作系统、Docker版本、镜像版本等信息

如需进一步的技术支持，请提供：
- 完整的错误信息截图或日志
- 使用的具体命令
- 输入文件样例（如CSV文件内容）
- 操作系统和Docker版本信息

---

**祝您使用愉快！** 如有任何改进建议，欢迎反馈。