# Tshark-tool

**CTF 流量分析工具** — 基于 tshark的 pcap/pcapng 取证分析工具箱，专为 CTF 挑战赛设计。

## 功能一览


| 命令      | 功能                                     |
| --------- | ---------------------------------------- |
| `info`    | 显示 pcap 文件基本信息与协议层级         |
| `ftp`     | FTP 会话分析 + 文件提取                  |
| `http`    | HTTP 流量分析 + POST/响应数据提取        |
| `all`     | 全协议综合分析（FTP + HTTP）             |
| `analyze` | 一站式分析 + 提取 + 敏感信息扫描         |
| `extract` | 从 pcap 提取 ZIP / hex 数据 / 自定义过滤 |
| `hex`     | Hex 编码/解码与 Hex dump                 |
| `base64`  | Base64 解码                              |
| `zip`     | ZIP 信息查看 + 密码暴力破解              |

## 安装

### 依赖

- **Python 3.11+**
- **TShark**（Wireshark）— [下载 Wireshark](https://www.wireshark.org/download.html)
  - 确保 `tshark`（Windows 下为 `tshark.exe`）在系统 PATH 中

### 验证

```bash
python tshark_tool.py --version
# 输出示例: Tshark-tool 1.0.0 (tshark: TShark (Wireshark) 4.6.4)
```

## 用法

### `info` — 文件信息

```bash
python tshark_tool.py info capture.pcap
# 显示文件大小、路径、tshark 版本、协议层级
```

### `ftp` — FTP 分析

```bash
# 基础分析
python tshark_tool.py ftp capture.pcap

# 提取 FTP-data 传输的文件
python tshark_tool.py ftp capture.pcap --extract
```

自动识别：登录凭据（USER/PASS）、传输文件名（RETR/STOR）、FTP-data 流中的实际文件。

### `http` — HTTP 分析

```bash
# 基础分析
python tshark_tool.py http capture.pcap

# 提取 POST 数据和 HTTP 响应文件
python tshark_tool.py http capture.pcap --extract --output ./output

# 配合附加过滤条件
python tshark_tool.py http capture.pcap --filter 'http.request.method == POST'
```

### `all` — 全协议综合分析

```bash
python tshark_tool.py all capture.pcap
python tshark_tool.py all capture.pcap --extract --output ./output
```

依次输出：协议层级 → FTP 摘要 → HTTP 摘要。`--extract` 模式还提取 FTP 文件、ZIP 文件和 HTTP 对象。

### `analyze` — 一站式分析（推荐）

```bash
python tshark_tool.py analyze capture.pcap -o ./output
```

自动执行 5 步：

1. 协议层级统计
2. FTP 分析
3. HTTP 分析
4. 提取所有文件（FTP data / ZIP / HTTP 对象 / POST 数据 / 响应数据）
5. 敏感信息扫描（凭据、Base64 编码数据、非 200 响应码）

### `extract` — 文件提取

```bash
# 从 pcap 提取 ZIP 文件
python tshark_tool.py extract zip capture.pcap

# hex 转二进制文件
python tshark_tool.py extract hex "504b0304..." output.zip

# hex dump 文件转二进制
python tshark_tool.py extract hex-file dump.txt output.zip

# 使用 tshark 过滤条件提取数据
python tshark_tool.py extract filter capture.pcap "icmp" --field data.data
```

### `hex` — Hex 操作

```bash
# hex 字符串解码为文本
python tshark_tool.py hex decode "48656c6c6f"

# 二进制文件生成 hex dump
python tshark_tool.py hex dump file.bin
```

### `base64` — Base64 解码

```bash
# 输出到 stdout
python tshark_tool.py base64 "SGVsbG8gd29ybGQ="

# 保存到文件
python tshark_tool.py base64 "SGVsbG8gd29ybGQ=" --output decoded.txt
```

### `zip` — ZIP 操作

```bash
# 查看 ZIP 文件内容
python tshark_tool.py zip info encrypted.zip

# 带密码查看
python tshark_tool.py zip info encrypted.zip --password "secret"

# 暴力破解密码（默认 4 位数字）
python tshark_tool.py zip crack encrypted.zip

# 自定义长度和字符集
python tshark_tool.py zip crack encrypted.zip --max-len 6 --chars "abcdefghijklmnopqrstuvwxyz"

# 使用字典
python tshark_tool.py zip crack encrypted.zip --wordlist rockyou.txt
```

暴力破解成功后会自动打印提取的文件内容预览。

## 项目结构

```
tshark_tool.py          # CLI 入口，参数解析 + 命令分发
core/
├── __init__.py         # 模块导出
├── exceptions.py       # 异常层次结构
├── logconfig.py        # 日志配置
├── tshark_wrapper.py   # tshark CLI 封装（缓存、过滤、流追踪、导出）
└── utils.py            # 纯 Python 工具：hex/base64 编解码、ZIP 破解、文件类型检测
modules/
├── __init__.py         # 模块导出
├── ftp_analyzer.py     # FTP 协议分析
├── http_analyzer.py    # HTTP 协议分析
└── extractor.py        # 文件提取（hex 过滤、ZIP 扫描、hex→文件）
```

### 核心模块说明


| 模块                | 职责                                   | 依赖外部工具 |
| ------------------- | -------------------------------------- | :----------: |
| `tshark_wrapper.py` | 封装 tshark 子进程调用，带 LRU 缓存    |    tshark    |
| `utils.py`          | hex/b64 编解码、ZIP 破解、文件魔数识别 |      无      |
| `ftp_analyzer.py`   | 解析 FTP 会话、凭据、文件传输          |    tshark    |
| `http_analyzer.py`  | 解析 HTTP 请求/响应、POST 数据         |    tshark    |
| `extractor.py`      | 按过滤条件提取数据、ZIP 自动扫描       |    tshark    |

## 依赖关系

```
tshark_tool.py
  ├── core/exceptions.py         (无依赖)
  ├── core/logconfig.py          (stdlib logging)
  ├── core/tshark_wrapper.py     → core/exceptions.py
  ├── core/utils.py              → core/exceptions.py
  ├── modules/ftp_analyzer.py    → core/tshark_wrapper.py, core/utils.py
  ├── modules/http_analyzer.py   → core/tshark_wrapper.py, core/utils.py
  └── modules/extractor.py       → core/tshark_wrapper.py, core/utils.py
```

## 适用场景

- CTF 比赛中的 **pcap 取证** 类题目
- 从网络流量中 **提取隐藏文件**（ZIP、图片、文本）
- **弱密码爆破**（FTP 凭据、ZIP 密码）
- HTTP **敏感数据扫描**（POST 参数中的 key/flag/token）
- 快速 **协议概览** 与 **流量统计**
