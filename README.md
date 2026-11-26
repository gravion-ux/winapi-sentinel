<p align="center"><img src="assets/banner.svg" alt="winapi-sentinel banner" width="100%"/></p>

# WinAPI Sentinel

[![CI](https://github.com/gravion-ux/winapi-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/gravion-ux/winapi-sentinel/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Static triage for risky Windows API usage patterns in C, C++, and Python source code.**

WinAPI Sentinel turns offensive Windows API knowledge into a
defensive review tool: it never executes the code it
scans, it flags single sensitive calls and multi-call chains (such as the
OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread
injection sequence), and every finding carries file/line evidence.

## Usage

```bash
pip install -e .
winapi-sentinel scan examples/inject_sample.c
winapi-sentinel scan path/to/file.c --json
```

Exit code is non-zero when a high or critical finding is present, so the
tool drops cleanly into CI.

## What it detects

- Remote-injection primitives and the full injection chain
- Hook and key-state polling patterns used by keyloggers
- Shell execution, registry persistence writes, and cross-process opens

## License

MIT
