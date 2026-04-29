# XiLing SBOM Analyzer User Manual

## Overview

XiLing SBOM Analyzer is a Docker container-based automated security assessment tool. It is designed to perform security analysis on source code repositories, batches of source code packages, or SBOM files and generate comprehensive reports. This manual provides guidance on loading the image and executing scans.

## System Requirements

- **Docker**: Version 18.09.1 or higher
- **Disk Space**: At least 3GB free space
- **Memory**: 4GB or more recommended
- **Network**: Required to access external software repositories and vulnerability databases

## Loading the Image

If you have obtained the offline image file, please follow these steps:

1. Obtain the `xiling-analyzer-latest.tar` image file.
2. Open a terminal and navigate to the directory containing the file.
3. Execute the following command to load the image:

```bash
docker load -i xiling-analyzer-latest.tar
```

4. Verify the loading was successful:

```bash
docker images | grep xiling-analyzer
```

## Usage Guide

### Scan Mode Overview

Choose one of the following three modes based on your requirements:

| Mode | Parameter | Input Source | Typical Use Case |
| :--- | :--- | :--- | :--- |
| **Repository Scan** | `--repo` / `-r` | Online Repository URL | Scanning packages for a specific distribution |
| **Batch Scan** | `--batch` / `-b` | Local CSV file | Bulk scanning of multiple specified source projects |
| **SBOM Analysis** | `--sbom` / `-s` | SBOM file (SPDX 2.x) | In-depth analysis based on an existing SBOM |

### Basic Command Structure

All scan modes follow a consistent command format:

```bash
docker run --rm -v <host_output_dir>:/app/output xiling-analyzer:latest <scan_mode> --output /app/output [other_parameters]
```

---

### Mode 1: Scanning a Single Repository

This mode is designed for online software repositories and supports two methods:

#### Method A: Automatic Scanning of Latest Packages (Recommended)
Provide the repository root URL; the tool automatically detects and scans the latest package information.

**Command Format:**
```bash
docker run --rm -v <host_output_dir>:/app/output xiling-analyzer:latest --repo <repository_root_URL> --output /app/output
```

**Usage Example:**
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

#### Method B: Specifying a specific primary.xml file
Provide the full URL to a `primary.xml.gz` file. Useful for scanning specific historical versions.

**Command Format:**
```bash
docker run --rm -v <host_output_dir>:/app/output xiling-analyzer:latest --repo <primary_xml_URL> --output /app/output
```

---

### Mode 2: Batch Scan

Use a CSV file to define multiple scan tasks simultaneously. Ideal for unified evaluation of multiple projects.

**Command Format:**
```bash
docker run --rm -v <host_data_dir>:/app/data -v <host_output_dir>:/app/output xiling-analyzer:latest --batch /app/data/<csv_file> --output /app/output
```

**CSV File Format:**

| Field | Description | Example |
| :--- | :--- | :--- |
| `name` | Package Name | foo |
| `version` | Version Number | 1.1.1 |
| `type` | Source Type (git/url) | git |
| `path` | Repository or Download URL | [https://github.com/foo/foo.git](https://github.com/foo/foo.git) |

**Example CSV Content:**
```csv
name,version,type,path
foo,1.1.1,git,https://github.com/foo/foo.git
bar,1.0,url,https://github.com/bar/bar/archive/refs/tags/v1.0.tar.gz
baz,2.3.0,git,https://gitlab.com/baz/baz-project.git
```

**Usage Example:**
```bash
docker run --rm -v $(pwd):/app/data -v $(pwd)/reports:/app/output xiling-analyzer:latest \
  --batch /app/data/batch.csv \
  --output /app/output
```

---

### Mode 3: SBOM Scan

Perform security analysis based on an existing SBOM file.

**Command Format:**
```bash
docker run --rm -v <host_data_dir>:/app/data -v <host_output_dir>:/app/output xiling-analyzer:latest --sbom /app/data/<SBOM_file> --output /app/output
```

> **Note**: Currently, only **SPDX 2.X** format is supported.

---

## Advanced Configuration

### Using a Configuration File

Customize scan behavior via a JSON configuration file.

**Configuration Example (`config.json`):**
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

**Key Parameter Descriptions:**

| Parameter | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| `general.cve_only` | Boolean | `true`: Show only CVEs; `false`: Show all vulnerabilities | `false` |
| `general.author` | String | Report author name | - |
| `batch_scan.include_file_patterns` | Array | File patterns included for license analysis | [Common languages] |
| `batch_scan.summary_display` | Boolean | Whether to show scan summary in console | `true` |

**Command Example with Config:**
```bash
docker run --rm -v $(pwd)/reports:/app/output -v $(pwd)/config.json:/app/config.json xiling-analyzer:latest \
  --repo <repository_URL> \
  --output /app/output \
  --config /app/config.json
```

### Optional Parameters

- `--max-workers <number>`: Set maximum concurrent threads (Default: CPU core count).
- `--disable-tqdm`: Disable progress bars (recommended for CI/CD environments).
- `--config <path>`: Specify external configuration file path.

**Example:**
```bash
docker run --rm -v ./reports:/app/output xiling-analyzer:latest \
  --repo <repository_URL> \
  --output /app/output \
  --max-workers 4 \
  --disable-tqdm
```

## Output Results

Reports are saved in the specified output directory:

| File/Directory | Format | Description |
| :--- | :--- | :--- |
| `Security_Assessment_Report.docx` | Word | Detailed security assessment report |
| `Security_Assessment_Report.pdf` | PDF | Report for distribution |
| `analysis_output/` | Directory | Raw scan data and assets |
| ├── `vulnerability_scan_results` | JSON | Detailed vulnerability data for all components |
| ├── `license_scan_results` | JSON | License detection and analysis results |
| └── `license_distribution_chart` | PNG | Visualization of license distribution |

## Troubleshooting

### Common Issues

#### Q: "OpenBLAS" error during runtime
**Error:** `pthread_create failed... Operation not permitted`

**Solution:** Add the `--security-opt seccomp=unconfined` flag to your Docker command:
```bash
docker run --rm --security-opt seccomp=unconfined ...
```

### Problem Diagnosis Steps

1. **Check Docker Environment**: `docker version` and `docker info`.
2. **Verify Image**: `docker images | grep xiling-analyzer`.
3. **Check Permissions**: Ensure the host directory is writable and not a system-protected path (like `/root`).
4. **Validate Input**: Check CSV encoding/separators and ensure SBOM is SPDX 2.X.

## Getting Support

1. **Review Documentation**: Check if the issue is addressed here.
2. **Check Configuration**: Confirm Docker version and disk space.
3. **Collect Information**: Record complete logs and the exact command used.

For technical support, please provide:
- Screenshots or text logs of the error.
- The command you executed.
- Sample input files (e.g., CSV snippet).
- OS and Docker version details.

---

**Happy analyzing!** We welcome your feedback and suggestions.