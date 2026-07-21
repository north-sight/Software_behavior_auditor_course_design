# cs-test-2026 IDA 自动化静态识别插件说明

## 文件清单

1. `ida_cstest2026_behavior_auditor.py`：IDA Pro IDAPython 自动化静态识别插件源码。
2. `cs-test-2026_ida_audit_expected_result.md`：针对 cs-test-2026 的 Markdown 预期输出样例。
3. `cs-test-2026_ida_audit_expected_result.json`：针对 cs-test-2026 的 JSON 预期输出样例。
4. `2026春《基于TCP流重组的软件行为分析》课程设计源代码说明-IDA插件-信安2304-U202310678-唐辰旸.docx`：源代码说明文件。

## 运行环境

1. IDA Pro，启用 IDAPython。
2. 样本文件为从 `cstest2026-do.pcapng` 中恢复的 `cs-test-2026`。
3. 首次打开样本后，应等待 IDA 自动分析完成，再运行插件脚本。

## 使用方法

1. 在 IDA Pro 中打开 `cs-test-2026`。
2. 等待函数、字符串和交叉引用分析完成。
3. 选择 `File -> Script file...`，运行 `ida_cstest2026_behavior_auditor.py`。
4. 插件输出 `cs-test-2026_ida_audit_result.md` 和 `cs-test-2026_ida_audit_result.json`。

## 识别目标

1. 自动识别 4 个漏洞：strncpy 栈缓冲区溢出、Double Free、Use After Free、整数溢出导致堆越界写。
2. 自动识别 7 个恶意代码行为：删除认证日志、文件重命名、修改脚本权限、执行本地脚本、开启 nc 监听、fork 型资源消耗、关闭 SELinux。
3. 输出函数名称、调用地址、静态证据、触发条件和计数校验结果。
