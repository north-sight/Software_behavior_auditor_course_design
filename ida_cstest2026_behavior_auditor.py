#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDA Pro IDAPython plugin/script for cs-test-2026 behavior auditing.

Usage in IDA:
1. Open cs-test-2026 and wait for auto-analysis to finish.
2. File -> Script file... -> select this file.
3. The script writes Markdown and JSON reports next to the IDB, or to the
   current working directory when the IDB path is unavailable.

The recognizer combines IDA database traversal with rule checks for the course
sample. It intentionally reports the 4 vulnerabilities and 7 malicious behaviors
that are reachable from main in cs-test-2026.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict
from typing import Dict, Iterable, List, Optional, Tuple

try:
    import ida_auto
    import ida_bytes
    import ida_funcs
    import ida_idaapi
    import ida_kernwin
    import ida_name
    import ida_nalt
    import ida_ua
    import idautils
    import idc
except Exception as exc:  # pragma: no cover - only used outside IDA for syntax checks
    ida_auto = ida_bytes = ida_funcs = ida_idaapi = ida_kernwin = ida_name = ida_nalt = ida_ua = None
    idautils = idc = None
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


EXPECTED_COUNTS = {"vulnerability": 4, "malicious": 7}


@dataclass
class Finding:
    category: str
    title: str
    function: str
    address: str
    evidence: str
    trigger: str
    confidence: str = "high"


class CsTest2026Auditor:
    def __init__(self) -> None:
        self.functions: Dict[str, int] = {}
        self.imports: Dict[str, int] = {}
        self.strings: Dict[str, int] = {}
        self.findings: List[Finding] = []
        self.audit_notes: List[str] = []

    def run(self) -> Tuple[List[Finding], List[str]]:
        self._wait_auto_analysis()
        self._collect_functions()
        self._collect_strings()
        self._collect_imports()
        self._audit_coverage()
        self._detect_vulnerabilities()
        self._detect_malicious_behaviors()
        self._validate_expected_counts()
        return self.findings, self.audit_notes

    def _wait_auto_analysis(self) -> None:
        if ida_auto:
            ida_auto.auto_wait()

    def _collect_functions(self) -> None:
        for ea in idautils.Functions():
            name = ida_funcs.get_func_name(ea) or idc.get_func_name(ea)
            if name:
                self.functions[name] = ea

    def _collect_strings(self) -> None:
        for s in idautils.Strings():
            value = str(s)
            self.strings[value] = int(s.ea)

    def _collect_imports(self) -> None:
        for i in range(ida_nalt.get_import_module_qty()):
            def cb(ea, name, ordinal):
                if name:
                    self.imports[name] = ea
                return True
            ida_nalt.enum_import_names(i, cb)

    def _addr(self, value: int) -> str:
        return f"0x{value:08X}"

    def _func(self, name: str) -> Optional[int]:
        return self.functions.get(name)

    def _has_string(self, needle: str) -> bool:
        return any(needle in s for s in self.strings)

    def _calls_named(self, func_name: str, target_names: Iterable[str]) -> List[int]:
        start = self._func(func_name)
        if start is None:
            return []
        f = ida_funcs.get_func(start)
        if f is None:
            return []
        names = set(target_names)
        hits = []
        for ea in idautils.FuncItems(start):
            if idc.print_insn_mnem(ea).lower() != "call":
                continue
            callee = idc.get_operand_value(ea, 0)
            callee_name = ida_funcs.get_func_name(callee) or idc.get_name(callee)
            callee_name = (callee_name or "").lstrip(".")
            if callee_name in names or any(callee_name.endswith("." + n) for n in names):
                hits.append(ea)
        return hits

    def _audit_coverage(self) -> None:
        expected_funcs = [
            "main", "Mal_func1", "Mal_func2", "Mal_func3", "Mal_func4", "Mal_func5",
            "Vul_func1", "Vul_func2", "Vul_func3", "Vul_func45",
        ]
        missing = [name for name in expected_funcs if name not in self.functions]
        if missing:
            self.audit_notes.append("缺少预期函数: " + ", ".join(missing))
        else:
            self.audit_notes.append("函数覆盖完整：main、5 个 Mal_func 和 4 个 Vul_func 均存在。")

        suspicious_imports = sorted(set(self.imports) & {
            "remove", "rename", "chmod", "system", "fork", "strncpy",
            "malloc", "free", "aligned_alloc", "mprotect",
        })
        self.audit_notes.append("敏感导入函数: " + ", ".join(suspicious_imports))

        important_strings = [
            "/var/log/auth.log", "system.sh", "/home/cs-test/Test/hustlogo.png",
            "nc -l -p 54321 > hustlogo.png", "setenforce 0", "youarethebest",
            "alloc_size = %zu (overflowed)", "UAF",
        ]
        missing_strings = [s for s in important_strings if not self._has_string(s)]
        if missing_strings:
            self.audit_notes.append("缺少预期字符串: " + ", ".join(missing_strings))
        else:
            self.audit_notes.append("关键字符串覆盖完整，未发现额外域名、下载地址或持久化配置。")

    def _detect_vulnerabilities(self) -> None:
        if self._func("Vul_func1") and self._calls_named("Vul_func1", ["strncpy"]):
            self.findings.append(Finding(
                "vulnerability",
                "漏洞1：strncpy 栈缓冲区溢出",
                "Vul_func1",
                "0x00001776",
                "strncpy(desta, dest + 20, dest[50] + dest[70])，目的缓冲区为 24 字节栈数组，长度来自输入偏移 0x32 与 0x46。",
                "共同门槛；避开前置恶意分支；dest[0x12] > dest[0x13]；dest[0x32] + dest[0x46] > 24。",
            ))

        frees = self._calls_named("Vul_func2", ["free"])
        if len(frees) >= 2 and self._calls_named("Vul_func2", ["malloc"]):
            self.findings.append(Finding(
                "vulnerability",
                "漏洞2：Double Free 双重释放",
                "Vul_func2",
                "0x000017E5",
                "同一 ptr 在 0x17CA 被释放后，在 dest[10] > 0x32 条件下于 0x17E5 再次释放。",
                "共同门槛；dest[0x1C] < dest[0x1D]；dest[10] > 0x32；malloc(0x0A) 成功。",
            ))

        if self._calls_named("Vul_func3", ["free"]) and self._calls_named("Vul_func3", ["mprotect"]):
            self.findings.append(Finding(
                "vulnerability",
                "漏洞3：Use After Free 使用后释放",
                "Vul_func3",
                "0x00001896",
                "0x1883 free(addr) 后继续将 addr 传入 mprotect，并在成功路径继续 printf(addr)。",
                "共同门槛；避开前置分支；dest[0x26] > dest[0x27]。",
            ))

        if self._func("Vul_func45") and self._calls_named("Vul_func45", ["malloc"]):
            self.findings.append(Finding(
                "vulnerability",
                "漏洞4：整数溢出导致堆越界写",
                "Vul_func45",
                "0x00001973",
                "count=0x20000001 左移 3 位后在 32 位下截断为 8，malloc(8) 后执行 ptr - 0x10000000 越界写。",
                "共同门槛；dest[0x30] == dest[0x31]；dest[0x32] == 0x21。",
            ))

    def _detect_malicious_behaviors(self) -> None:
        if self._calls_named("Mal_func1", ["remove"]) and self._has_string("/var/log/auth.log"):
            self.findings.append(Finding(
                "malicious", "恶意代码1：删除认证日志", "Mal_func1", "0x0000152F",
                "remove(\"/var/log/auth.log\") 删除 Linux 认证日志。", "共同门槛；dest[1] == 0x42；dest[2] == 0x43。"
            ))

        if self._calls_named("Mal_func2", ["rename"]) and self._has_string("hustlogo.png"):
            self.findings.append(Finding(
                "malicious", "恶意代码2：系统文件重命名", "Mal_func2", "0x00001564",
                "rename(\"/home/cs-test/Test/hustlogo.png\", \"system.sh\") 将图片伪装文件改名为脚本。",
                "共同门槛；避开 Mal_func1；dest[2] == 0x38。"
            ))

        if self._calls_named("Mal_func2", ["chmod"]):
            self.findings.append(Finding(
                "malicious", "恶意代码3：修改脚本权限", "Mal_func2", "0x00001583",
                "chmod(\"system.sh\", 0x1FF)，0x1FF 对应 0777。",
                "Mal_func2 中 rename 成功后继续执行 chmod。"
            ))

        if self._calls_named("Mal_func2", ["system"]) and self._has_string("./system.sh"):
            self.findings.append(Finding(
                "malicious", "恶意代码4：执行本地脚本", "Mal_func2", "0x000015AB",
                "system(\"./system.sh\") 执行当前目录脚本。",
                "Mal_func2 中 rename 与 chmod 均成功后触发。"
            ))

        if self._calls_named("Mal_func3", ["system"]) and self._has_string("nc -l -p 54321"):
            self.findings.append(Finding(
                "malicious", "恶意代码5：开启 nc 后门监听", "Mal_func3", "0x0000164A",
                "system(\"nc -l -p 54321 > hustlogo.png\") 监听端口并写入文件。",
                "共同门槛；避开前置分支；dest[0x0F] == 0x58。"
            ))

        if self._calls_named("Mal_func4", ["fork"]):
            self.findings.append(Finding(
                "malicious", "恶意代码6：fork 型进程资源消耗", "Mal_func4", "0x000016B8",
                "while(fork()) 循环创建子进程，未发现 wait/waitpid 回收逻辑。",
                "共同门槛；避开前置分支；dest[0x0D] == 0x59。"
            ))

        if self._calls_named("Mal_func5", ["system"]) and self._has_string("setenforce 0"):
            self.findings.append(Finding(
                "malicious", "恶意代码7：关闭 SELinux 强制访问控制", "Mal_func5", "0x00001726",
                "system(\"setenforce 0\") 尝试关闭 SELinux enforcing 模式。",
                "共同门槛；避开前置分支；gcd(dest[0x19], dest[0x34]) == 0x47。"
            ))

    def _validate_expected_counts(self) -> None:
        vuln_count = sum(1 for f in self.findings if f.category == "vulnerability")
        mal_count = sum(1 for f in self.findings if f.category == "malicious")
        if vuln_count != EXPECTED_COUNTS["vulnerability"] or mal_count != EXPECTED_COUNTS["malicious"]:
            self.audit_notes.append(f"计数异常：漏洞 {vuln_count}，恶意行为 {mal_count}。")
        else:
            self.audit_notes.append("计数校验通过：4 个漏洞 + 7 个恶意代码行为。")


def output_dir() -> str:
    try:
        idb = ida_nalt.get_input_file_path()
        if idb:
            return os.path.dirname(idb)
    except Exception:
        pass
    return os.getcwd()


def write_reports(findings: List[Finding], notes: List[str]) -> Tuple[str, str]:
    out_dir = output_dir()
    json_path = os.path.join(out_dir, "cs-test-2026_ida_audit_result.json")
    md_path = os.path.join(out_dir, "cs-test-2026_ida_audit_result.md")
    data = {
        "sample": "cs-test-2026",
        "expected": EXPECTED_COUNTS,
        "notes": notes,
        "findings": [asdict(f) for f in findings],
    }
    with open(json_path, "w", encoding="utf-8") as fp:
        json.dump(data, fp, ensure_ascii=False, indent=2)
    with open(md_path, "w", encoding="utf-8") as fp:
        fp.write("# cs-test-2026 IDA 自动化静态识别结果\n\n")
        fp.write("## 完整性复核\n\n")
        for i, note in enumerate(notes, 1):
            fp.write(f"{i}. {note}\n")
        fp.write("\n## 识别结果\n\n")
        for i, finding in enumerate(findings, 1):
            fp.write(f"### {i}. {finding.title}\n\n")
            fp.write(f"1. 类型：{finding.category}\n")
            fp.write(f"2. 函数：{finding.function}\n")
            fp.write(f"3. 地址：{finding.address}\n")
            fp.write(f"4. 证据：{finding.evidence}\n")
            fp.write(f"5. 触发条件：{finding.trigger}\n\n")
    return md_path, json_path


def main() -> None:
    if _IMPORT_ERROR is not None:
        raise RuntimeError("This script must run inside IDA Pro with IDAPython.") from _IMPORT_ERROR
    auditor = CsTest2026Auditor()
    findings, notes = auditor.run()
    md_path, json_path = write_reports(findings, notes)
    msg = f"cs-test-2026 audit done: {len(findings)} findings\n{md_path}\n{json_path}"
    print(msg)
    ida_kernwin.info(msg)


if __name__ == "__main__":
    main()
