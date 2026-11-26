from winapi_sentinel import analyze_source

INJECT = """
HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
LPVOID mem = VirtualAllocEx(h, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(h, mem, shellcode, size, NULL);
CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
"""

SAFE = """
int main() { printf("hello"); return 0; }
"""

HOOK = """
SetWindowsHookEx(WH_KEYBOARD_LL, proc, NULL, 0);
GetMessage(&msg, NULL, 0, 0);
"""


def test_injection_chain_detected():
    findings = analyze_source(INJECT)
    ids = {f.rule_id for f in findings}
    assert "CHAIN-INJECT" in ids
    assert any(f.severity == "critical" for f in findings)


def test_safe_code_clean():
    assert analyze_source(SAFE) == []


def test_hook_chain_detected():
    ids = {f.rule_id for f in analyze_source(HOOK)}
    assert "CHAIN-HOOK" in ids


def test_line_numbers_and_evidence():
    findings = analyze_source("int a;\nCreateRemoteThread(x);\n")
    assert findings[0].line == 2
    assert "CreateRemoteThread" in findings[0].evidence
