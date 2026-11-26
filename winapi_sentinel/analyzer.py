"""Rule-based static analysis for offensive Windows API patterns.

The analyzer never executes the code it scans. It looks for single API
calls and for multi-call chains that together describe classic process
injection, keylogging, and persistence techniques, then reports each
finding with file/line evidence so a reviewer can verify it quickly.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

SINGLE_RULES = [
    ("WINAPI-001", "CreateRemoteThread", "high", "Remote thread creation is a core process-injection primitive."),
    ("WINAPI-002", "WriteProcessMemory", "high", "Writing into another process memory is an injection primitive."),
    ("WINAPI-003", "VirtualAllocEx", "medium", "Remote memory allocation commonly precedes injection."),
    ("WINAPI-004", "SetWindowsHookEx", "medium", "Global hooks can capture keystrokes and messages."),
    ("WINAPI-005", "GetAsyncKeyState", "medium", "Polling key state is a keylogging pattern."),
    ("WINAPI-006", "ShellExecute", "low", "Shell execution should be reviewed for untrusted input."),
    ("WINAPI-007", "RegSetValueEx", "low", "Registry writes can establish persistence; review the key path."),
    ("WINAPI-008", "OpenProcess", "low", "Opening other processes is sensitive; review requested access rights."),
]

CHAINS = [
    ("CHAIN-INJECT", ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"], "critical", "Full remote-injection chain: open, allocate, write, execute."),
    ("CHAIN-HOOK", ["SetWindowsHookEx", "GetMessage"], "medium", "Hook plus message loop pattern used by keyloggers."),
]


@dataclass
class Finding:
    rule_id: str
    api: str
    severity: str
    message: str
    line: int
    evidence: str

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "api": self.api,
            "severity": self.severity,
            "message": self.message,
            "line": self.line,
            "evidence": self.evidence,
        }


def analyze_source(source: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.splitlines()
    seen: dict[str, int] = {}
    chain_apis = {api for _, apis, _, _ in CHAINS for api in apis}
    for idx, line in enumerate(lines, start=1):
        for api in chain_apis:
            if re.search(rf"\b{api}\b", line):
                seen.setdefault(api, idx)
        for rule_id, api, severity, message in SINGLE_RULES:
            if re.search(rf"\b{api}\b", line):
                findings.append(Finding(rule_id, api, severity, message, idx, line.strip()))
                seen.setdefault(api, idx)
    for rule_id, apis, severity, message in CHAINS:
        if all(api in seen for api in apis):
            line_no = max(seen[api] for api in apis)
            findings.append(Finding(rule_id, "+".join(apis), severity, message, line_no, lines[line_no - 1].strip()))
    return sorted(findings, key=lambda f: (f.line, f.rule_id))


def analyze_path(path: str | Path) -> list[Finding]:
    return analyze_source(Path(path).read_text(encoding="utf-8", errors="ignore"))
