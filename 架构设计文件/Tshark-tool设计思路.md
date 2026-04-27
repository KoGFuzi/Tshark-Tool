注：该工具应被设计为跨linux和windows平台。
## 一、Tshark的主要参数
```
TShark (Wireshark) 4.6.4 (v4.6.4-0-g93282876538d)
Dump and analyze network traffic.
See https://www.wireshark.org for more information.

Usage: tshark [options] ...

Capture interface:
  -i <interface>, --interface <interface>
                           name or idx of interface (def: first non-loopback)
  -f <capture filter>      packet filter in libpcap filter syntax
  -s <snaplen>, --snapshot-length <snaplen>
                           packet snapshot length (def: appropriate maximum)
  -p, --no-promiscuous-mode
                           don't capture in promiscuous mode
  -I, --monitor-mode       capture in monitor mode, if available
  -B <buffer size>, --buffer-size <buffer size>
                           size of kernel buffer in MiB (def: 2MiB)
  -y <link type>, --linktype <link type>
                           link layer type (def: first appropriate)
  --time-stamp-type <type> timestamp method for interface
  -D, --list-interfaces    print list of interfaces and exit
  -L, --list-data-link-types
                           print list of link-layer types of iface and exit
  --list-time-stamp-types  print list of timestamp types for iface and exit

Capture display:
  --update-interval        interval between updates with new packets, in milliseconds (def: 100ms)
Capture stop conditions:
  -c <packet count>        stop after n packets (def: infinite)
  -a <autostop cond.> ..., --autostop <autostop cond.> ...
                           duration:NUM - stop after NUM seconds
                           filesize:NUM - stop this file after NUM KB
                              files:NUM - stop after NUM files
                            packets:NUM - stop after NUM packets
Capture output:
  -b <ringbuffer opt.> ..., --ring-buffer <ringbuffer opt.>
                           duration:NUM - switch to next file after NUM secs
                           filesize:NUM - switch to next file after NUM KB
                              files:NUM - ringbuffer: replace after NUM files
                            packets:NUM - switch to next file after NUM packets
                           interval:NUM - switch to next file when the time is
                                          an exact multiple of NUM secs
                         printname:FILE - print filename to FILE when written
                                          (can use 'stdout' or 'stderr')
RPCAP options:
  -A <user>:<password>     use RPCAP password authentication
Input file:
  -r <infile>, --read-file <infile>
                           set the filename to read from (or '-' for stdin)

Processing:
  -2                       perform a two-pass analysis
  -M <packet count>        perform session auto reset
  -R <read filter>, --read-filter <read filter>
                           packet Read filter in Wireshark display filter syntax
                           (requires -2)
  -Y <display filter>, --display-filter <display filter>
                           packet displaY filter in Wireshark display filter
                           syntax
  -n                       disable all name resolutions (def: "mNd" enabled, or
                           as set in preferences)
  -N <name resolve flags>  enable specific name resolution(s): "mtndsNvg"
  -d <layer_type>==<selector>,<decode_as_protocol> ...
                           "Decode As", see the man page for details
                           Example: tcp.port==8888,http
  -H <hosts file>          read a list of entries from a hosts file, which will
                           then be written to a capture file. (Implies -W n)
  --enable-protocol <proto_name>
                           enable dissection of proto_name
  --disable-protocol <proto_name>
                           disable dissection of proto_name
  --only-protocols <protocols>
                           Only enable dissection of these protocols, comma
                           separated. Disable everything else
  --disable-all-protocols
                           Disable dissection of all protocols
  --enable-heuristic <short_name>
                           enable dissection of heuristic protocol
  --disable-heuristic <short_name>
                           disable dissection of heuristic protocol
Output:
  -w <outfile|->           write packets to a pcapng-format file named "outfile"
                           (or '-' for stdout). If the output filename has the
                           .gz extension, it will be compressed to a gzip archive
  --capture-comment <comment>
                           add a capture file comment, if supported
  -C <config profile>      start with specified configuration profile
  --global-profile         use the global profile instead of personal profile
  -F <output file type>    set the output file type; default is pcapng.
                           an empty "-F" option will list the file types
  -V                       add output of packet tree        (Packet Details)
  -O <protocols>           Only show packet details of these protocols, comma
                           separated
  -P, --print              print packet summary even when writing to a file
  -S <separator>           the line separator to print between packets
  -x                       add output of hex and ASCII dump (Packet Bytes)
  --hexdump <hexoption>    add hexdump, set options for data source and ASCII dump
     all                   dump all data sources (-x default)
     frames                dump only frame data source
     ascii                 include ASCII dump text (-x default)
     delimit               delimit ASCII dump text with '|' characters
     noascii               exclude ASCII dump text
     time                  include frame timestamp preamble
     notime                do not include frame timestamp preamble (-x default)
     help                  display help for --hexdump and exit
  -T pdml|ps|psml|json|jsonraw|ek|tabs|text|fields|?
                           format of text output (def: text)
  -j <protocolfilter>      protocols layers filter if -T ek|pdml|json selected
                           (e.g. "ip ip.flags text", filter does not expand child
                           nodes, unless child is specified also in the filter)
  -J <protocolfilter>      top level protocol filter if -T ek|pdml|json selected
                           (e.g. "http tcp", filter which expands all child nodes)
  -e <field>               field to print if -Tfields selected (e.g. tcp.port,
                           _ws.col.info)
                           this option can be repeated to print multiple fields
  -E<fieldsoption>=<value> set options for output when -Tfields selected:
     bom=y|n               print a UTF-8 BOM
     header=y|n            switch headers on and off
     separator=/t|/s|<char> select tab, space, printable character as separator
     occurrence=f|l|a      print first, last or all occurrences of each field
     aggregator=,|/s|<char> select comma, space, printable character as
                           aggregator
     quote=d|s|n           select double, single, no quotes for values
  -t (a|ad|adoy|d|dd|e|r|u|ud|udoy)[.[N]]|.[N]
                           output format of time stamps (def: r: rel. to first)
  -u s|hms                 output format of seconds (def: s: seconds)
  -l                       flush standard output after each packet
                           (implies --update-interval 0)
  -q                       be more quiet on stdout (e.g. when using statistics)
  -Q                       only log true errors to stderr (quieter than -q)
  -g                       enable group read access on the output file(s)
  -W n                     Save extra information in the file, if supported.
                           n = write network address resolution information
  -X <key>:<value>         eXtension options, see the man page for details
  -U tap_name              PDUs export mode, see the man page for details
  -z <statistics>          various statistics, see the man page for details
  --export-objects <protocol>,<destdir>
                           save exported objects for a protocol to a directory
                           named "destdir"
  --export-tls-session-keys <keyfile>
                           export TLS Session Keys to a file named "keyfile"
  --color                  color output text similarly to the Wireshark GUI,
                           requires a terminal with 24-bit color support
                           Also supplies color attributes to pdml and psml formats
                           (Note that attributes are nonstandard)
  --no-duplicate-keys      If -T json is specified, merge duplicate keys in an object
                           into a single key with as value a json array containing all
                           values
  --elastic-mapping-filter <protocols> If -G elastic-mapping is specified, put only the
                           specified protocols within the mapping file
  --temp-dir <directory>   write temporary files to this directory
                           (default: C:\Users\26086\AppData\Local\Temp)
  --compress <type>        compress the output file using the type compression format

Diagnostic output:
  --log-level <level>      sets the active log level ("critical", "warning", etc.)
  --log-fatal <level>      sets level to abort the program ("critical" or "warning")
  --log-domains <[!]list>  comma-separated list of the active log domains
  --log-fatal-domains <list>
                           list of domains that cause the program to abort
  --log-debug <[!]list>    list of domains with "debug" level
  --log-noisy <[!]list>    list of domains with "noisy" level
  --log-file <path>        file to output messages to (in addition to stderr)

Miscellaneous:
  -h, --help               display this help and exit
  -v, --version            display version info and exit
  -o <name>:<value> ...    override preference setting
  -K <keytab>              keytab file to use for kerberos decryption
  -G [report]              dump one of several available reports and exit
                           default report="fields"
                           use "-G help" for more help
```

以下是基于需求设计的程序架构思路，采用模块化、可扩展的方式组织代码，便于后续实现与维护。

---

## 二、整体设计目标
- **输入**：PCAP 文件路径、风险等级 `risk`（1 或 2）、分析模式 `model`（`sql` / `ftp` / `httpd` / `extra`，`risk=2` 时有效）
- **处理**：调用 TShark 完成基础流量分析，并根据 `model` 执行专项分析
- **输出**：在 PCAP 文件同级目录下生成结果文件夹，存放所有分析产物（拆分后的 PCAP、IP 列表、会话信息、专项分析报告、提取的文件等）

---

## 三、主流程架构

```
main.py
├── 参数解析（argparse）
│   ├── -r/--pcap     (必选)
│   ├── --risk        (默认 1)
│   └── --model       (risk=2 时必选)
├── 初始化 TShark 路径与环境检查
├── 创建输出目录（pcap 同目录下，以 “pcap文件名_analysis” 命名）
├── 基础分析模块（始终执行）
│   ├── 获取数据包摘要信息
│   ├── 收集时间格式
│   ├── 统计会话 IP 组（ip.src -> ip.dst）
│   ├── 提取去重所有 IP 端点
│   └── 按会话拆分数据包
├── 特殊分析模块（risk=2 时执行）
│   ├── 根据 model 分发至对应分析器
│   │   ├── SqlAnalyzer
│   │   ├── FtpAnalyzer
|   |   |—— ICMPAnalyzer
│   │   ├── HttpdAnalyzer
│   │   └── ExtraFileExtractor
│   └── 各分析器生成专项报告 / 导出文件
└── 输出最终汇总信息（日志/控制台）
```

---

## 四、核心模块设计

### 1. 参数与环境管理
- **类/函数**：`ConfigManager` / `parse_args()`
- 获取 `pcap` 路径，校验 `risk` 与 `model` 的合法性。
- 定位 TShark 可执行文件（优先环境变量，否则从配置文件读取）。
- 构建输出目录结构，例如 `./原文件名_analysis/`，内部可分子目录：
  ```
  pcap_analysis/
  ├── basic/
  │   ├── summary.txt
  │   ├── time_format.txt
  │   ├── sessions.txt
  │   ├── all_ips.txt
  │   └── split_pcaps/        # 拆分后的会话 pcap 文件
  └── special/
      ├── sql_injection.txt
      └── extracted_files/    # 提取的 zip/png 等
  ```

### 2. TShark 调用器
- **类**：`TsharkRunner`
  - 封装 `subprocess.Popen` 调用，统一处理标准输出/错误、超时、异常。
  - 提供基础操作：
    - `run_command(args, timeout=...)` 返回 `(stdout, stderr)`
    - `get_summary(pcap, count=None, verbose=False)` 获取摘要
    - `get_time_format(pcap, format='ad')` 收集时间格式
    - `get_conversations(pcap, type='ip')` 获取会话（`-z conv,ip`）
    - `get_endpoints(pcap, type='ip')` 获取端点（`-z endpoints,ip`）
    - `filter_and_save(pcap, display_filter, output_pcap)` 按过滤条件导出

### 3. 基础分析处理器
- **类**：`BasicAnalyzer`
  - 组合 `TsharkRunner` 完成风险等级 1 的所有步骤：
    - 执行 `-r pcap`，`-r pcap -V`（限制输出行数/大小），`-r pcap -c5` 并写入 `summary.txt`
    - 执行 `-r pcap -t ad`，结果存 `time_format.txt`
    - 解析 `-r pcap` 的输出，通过正则 `ip.src ... → ip.dst` 生成会话 IP 组，写入 `sessions.txt`
    - 调用 `get_endpoints(pcap)` 提取去重 IP 列表，写入 `all_ips.txt`
    - 调用 `get_conversations(pcap, 'ip')` 获取会话 IP 对，循环生成 `split_pcaps/` 下的拆分数据包（命名如 `192.168.1.1to10.0.0.2.pcap`）
  - 返回所有输出文件的路径字典，供后续报告引用。

### 4. 特殊分析处理器（工厂 + 策略模式）
- **抽象基类**：`SpecialAnalyzer(ABC)`
  - 定义接口：`analyze(pcap_path, output_dir) -> report_path`
- **具体分析器**：
  - `SqlAnalyzer`：使用过滤语法 `http.request.uri contains "select" or "union" or ...`，统计可疑请求并将详细信息输出到 `special/sql_injection.txt`。
  - `FtpAnalyzer`：过滤 `ftp` 或 `ftp-data`，提取登录信息、文件传输记录等。
  - `ICMPAnalyzer`：过滤`icmp`的相关流量，提取包含数据的ICMP回显请求或者应答。
  - `HttpdAnalyzer`：检测攻击行为（如 XSS、命令注入、目录遍历），可基于预定义规则匹配 URI 或参数，输出告警列表。
  - `ExtraFileExtractor`：利用 TShark 的 `--export-objects` 功能导出 HTTP 对象或 FTP-DATA 中的文件，按类型（zip/png/...）保存到 `special/extracted_files/<类型>/`。
- **工厂函数**：`create_special_analyzer(model)` 返回对应的分析器实例。
- 每个分析器内部调用 `TsharkRunner` 执行命令，并解析结果。

### 5. 主控制器
- **类**：`PcapAnalysisManager`
  - 初始化时接收 `pcap`, `risk`, `model`，创建 `TsharkRunner` 和输出目录。
  - 方法 `run()`：
    1. 执行基础分析，得到基础结果路径。
    2. 如果 `risk==2` 且 `model` 有效，创建特殊分析器，传入原始 pcap 和 `special/` 目录，执行并收集报告。
    3. 打印最终汇总（结果保存位置、关键发现摘要）。
  - 所有操作日志记录到 `analysis.log`（位于输出根目录）。

---

## 五、扩展性设计要点
- **分析器插件化**：`SpecialAnalyzer` 子类只需实现 `analyze()`，通过注册机制（字典映射 `model->class`）即可扩展新的流量分析模式。
- **配置外置**：TShark 路径、过滤规则、输出模板等可放在 `config.yaml` 中，便于调整。
- **正则与过滤条件复用**：将会话 IP 提取、时间格式解析等正则规则封装为 `parsers.py`，提高复用性和可维护性。

---

## 六、数据存储规范
- 文本报告均使用 UTF-8 编码，每条记录一行或以 Markdown 表格组织。
- 拆分的 PCAP 保持与原始文件相同的捕获格式。
- 提取的文件按原始文件扩展名分类目录，并保留原始网络流中的文件名（必要时做安全处理防止路径遍历）。

---

## 七、运行示例（伪命令行）
```bash
# 基础分析
python pcap_analyzer.py -r capture.pcap

# 携带 SQL 注入检测的特殊分析
python pcap_analyzer.py -r capture.pcap --risk 2 --model sql

# 文件提取模式
python pcap_analyzer.py -r capture.pcap --risk 2 --model extra
```