#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
extract_raw_log_lines.py -- 从 ZenithProxy 日志中提取包含长 Base64 的聊天行

用途：调试扫描器时，直接查看原始日志行（含密文），确认格式是否匹配。

用法:
    py -3 extract_raw_log_lines.py <日志文件或目录...>

示例:
    py -3 extract_raw_log_lines.py "C:\\servers\\ZenithProxy\\logs"
    py -3 extract_raw_log_lines.py "\\\\server\\share\\logs"
"""
import os
import re
import sys
import zipfile

# ZenithProxy 聊天行
CHAT_RE = re.compile(r'\[(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\] \[Chat\] \[INFO\] (.*)$')

# 长 Base64（可能是加密载荷）
B64_RE = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')


def scan_text(text, source):
    """从文本中提取匹配行"""
    for line in text.splitlines():
        m = CHAT_RE.search(line)
        if not m:
            continue
        ts, body = m.group(1), m.group(2)
        if B64_RE.search(body):
            yield ts, line


def scan_file(path):
    """扫描单个文件（支持 .zip / .log / .txt / .tmp）"""
    print("=" * 70)
    print("FILE:", path)
    if path.lower().endswith('.zip'):
        try:
            with zipfile.ZipFile(path) as z:
                for name in z.namelist():
                    if not name.endswith(('.log', '.txt')):
                        continue
                    with z.open(name) as f:
                        text = f.read().decode('utf-8', errors='replace')
                    for ts, line in scan_text(text, name):
                        print("  ", line[:400])
        except Exception as e:
            print(f"  [error] {e}")
    else:
        try:
            with open(path, encoding='utf-8', errors='replace') as f:
                text = f.read()
            for ts, line in scan_text(text, path):
                print("  ", line[:400])
        except Exception as e:
            print(f"  [error] {e}")


def collect_files(paths):
    """收集所有待扫描文件"""
    files = []
    for p in paths:
        if os.path.isfile(p):
            files.append(p)
        elif os.path.isdir(p):
            for dp, _, fns in os.walk(p):
                for fn in fns:
                    if fn.lower().endswith(('.log', '.txt', '.tmp', '.zip')):
                        files.append(os.path.join(dp, fn))
    return sorted(set(files))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    files = collect_files(sys.argv[1:])
    print(f"Found {len(files)} log file(s)")
    for f in files:
        scan_file(f)


if __name__ == '__main__':
    main()
