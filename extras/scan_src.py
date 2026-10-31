#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scan_src.py -- 对 Java 源码目录做安全扫描（不执行任何东西）"""
import sys, os, re, json
from collections import defaultdict
import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DANGER = {
    '进程执行':   r'Runtime\s*\.\s*getRuntime|ProcessBuilder|\.exec\s*\(|CreateProcess',
    '网络':       r'java\.net\.|HttpURLConnection|URLConnection|Socket\s*\(|ServerSocket|InetSocketAddress',
    'HTTP客户端': r'okhttp|apache\.http|java\.net\.http|HttpClient|WebSocket',
    '文件写入':   r'FileOutputStream|FileWriter|RandomAccessFile|Files\.write|Files\.copy|PrintWriter\s*\(',
    '反射':       r'Class\.forName|loadClass\s*\(|setAccessible|defineClass|URLClassLoader',
    '加密':       r'Cipher\.getInstance|javax\.crypto|MessageDigest|Base64|SecretKey|AES|RSA',
    '系统信息':   r'System\.getenv|System\.getProperty|InetAddress|NetworkInterface|os\.name',
    '剪贴板':     r'Clipboard|Toolkit\.getSystemClipboard|java\.awt\.Robot',
    'Webhook':    r'discord\.com/api|webhook|telegram|t\.me/|api\.telegram',
    'HWID':       r'MachineGuid|csproduct|hardware|hwid|fingerprint|machineId|baseboard',
    '敏感文件':   r'options\.txt|launcher_profiles|accounts\.json|usercache|accessToken|refreshToken|\.ssh|id_rsa',
    '屏幕截图':   r'ImageIO|BufferedImage|Robot|screenshot',
    '注册表':     r'Advapi32|RegistryKey|winreg',
}

def scan_dir(root):
    print("=" * 78)
    print(f"  扫描源码目录: {root}")
    print("=" * 78)
    if not os.path.isdir(root):
        print("  ✗ 不是目录"); return

    java_files = []
    for dp, dn, fn in os.walk(root):
        for f in fn:
            if f.endswith('.java'):
                java_files.append(os.path.join(dp, f))
    print(f"  Java 文件数: {len(java_files)}")
    if not java_files:
        return

    total_lines = 0
    hits = defaultdict(list)
    for p in java_files:
        try:
            txt = open(p, encoding='utf-8', errors='replace').read()
        except Exception:
            continue
        total_lines += txt.count('\n') + 1
        rel = os.path.relpath(p, root)
        for cat, pat in DANGER.items():
            for m in re.finditer(pat, txt, re.I):
                line_no = txt[:m.start()].count('\n') + 1
                # 取该行
                line_start = txt.rfind('\n', 0, m.start()) + 1
                line_end = txt.find('\n', m.start())
                line = txt[line_start:line_end if line_end > 0 else len(txt)].strip()
                hits[cat].append((rel, line_no, line[:150]))

    print(f"  总行数: {total_lines:,}")
    print()

    # 汇总
    print("[危险模式汇总]")
    for cat in DANGER:
        hs = hits.get(cat, [])
        mark = '✅' if not hs else ('🔴' if len(hs) > 10 else '🟡')
        print(f"  {mark} {cat:<12} {len(hs):>6} 处")

    print()
    # 详细
    for cat in DANGER:
        hs = hits.get(cat, [])
        if not hs:
            continue
        print(f"\n--- {cat}（{len(hs)} 处，显示前 15）---")
        for rel, ln, line in hs[:15]:
            print(f"  {rel}:{ln}")
            print(f"      {line}")
        if len(hs) > 15:
            print(f"  ... 还有 {len(hs)-15} 处")

    # 文件写入/网络/hwid 的类级分布
    print()
    print("[按文件统计（网络/文件写入/HWID）]")
    for cat in ('网络', '文件写入', 'HWID', '进程执行', 'Webhook'):
        hs = hits.get(cat, [])
        if not hs: continue
        files = defaultdict(int)
        for rel, ln, line in hs:
            files[rel] += 1
        print(f"\n  {cat}:")
        for f, c in sorted(files.items(), key=lambda x: -x[1])[:10]:
            print(f"    {c:>3} 处  {f}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    scan_dir(sys.argv[1])
