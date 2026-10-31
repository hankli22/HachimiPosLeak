#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scan_zenith_ping2.py -- 扫描 ZenithProxy 日志，寻找 hachimi Ping2 泄露的坐标

原理：
  hachimi 客户端 Ping2 模块用 AES-128-CBC（全零 IV）加密 "EnemyHere{x,y,z,color}"
  经 Base64 编码后发到公共聊天。默认密钥 "IDKWTFTHIS"（Ping2.java:361）。
  如果玩家没改默认密钥，任何人都能解密日志中的密文。

用法：
  py -3 scan_zenith_ping2.py [日志目录...]
"""
import os
import re
import sys
import hashlib
import base64
import json

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
except ImportError:
    print("需要 pycryptodome: py -3 -m pip install pycryptodome")
    sys.exit(1)

# ── 默认密钥（Ping2.java:361）──
DEFAULT_KEY = "IDKWTFTHIS"

# 其他常见/可能的密钥
EXTRA_KEYS = ["", "hachimi", "Hachimi", "hachimiclient", "123456", "password",
              "IDKWTFTHIS", "idkwtfthis", "hachimi123"]

# Minecraft 颜色码
COLOR_RE = re.compile(r'§[0-9a-fk-orA-FK-OR]')
# 聊天行：  [2026/11/01 00:00:00] [Chat] [INFO] «sender» message
CHAT_RE = re.compile(r'\[(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\] \[Chat\] \[INFO\] (.*)$')
# Base64 token
B64_RE = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
# 目标明文
TARGET = "EnemyHere"


def derive_key(s: str) -> bytes:
    """Ping2.Lu() 等价实现：SHA-256(s)[0:16]"""
    return hashlib.sha256(s.encode('utf-8')).digest()[:16]


def try_decrypt(token: str, keys):
    """尝试用各密钥解密 Base64 token，返回 (plaintext, key) 或 None"""
    try:
        raw = base64.b64decode(token, validate=True)
    except Exception:
        return None
    if len(raw) == 0 or len(raw) % 16 != 0:
        return None
    for k in keys:
        try:
            cipher = AES.new(derive_key(k), AES.MODE_CBC, b'\x00' * 16)
            pt = unpad(cipher.decrypt(raw), 16)
            s = pt.decode('utf-8', errors='replace')
            if TARGET in s:
                return s, k
        except Exception:
            continue
    return None


def scan_file(path, keys, out):
    """扫描单个日志文件"""
    hits = []
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for lineno, line in enumerate(f, 1):
                line = line.rstrip('\n')
                m = CHAT_RE.search(line)
                if not m:
                    continue
                ts, body = m.group(1), m.group(2)
                # 清理颜色码
                clean = COLOR_RE.sub('', body)
                # 提取发送者： «name» 或 <name> 或 name:
                sender = '?'
                sm = re.match(r'[«<]([^»>]+)[»>]\s*(.*)$', clean)
                if sm:
                    sender, clean = sm.group(1), sm.group(2)
                else:
                    sm2 = re.match(r'([A-Za-z0-9_]{3,16})\s*[»>]\s*(.*)$', clean)
                    if sm2:
                        sender, clean = sm2.group(1), sm2.group(2)
                # 找 Base64 token
                for tok in B64_RE.findall(clean):
                    r = try_decrypt(tok, keys)
                    if r:
                        pt, k = r
                        hits.append({
                            'file': os.path.basename(path),
                            'line': lineno,
                            'time': ts,
                            'sender': sender,
                            'plaintext': pt,
                            'key': k,
                            'token': tok,
                        })
    except Exception as e:
        print(f"  [错误] {path}: {e}")
    return hits


def main():
    dirs = sys.argv[1:]
    if not dirs:
        print(__doc__)
        sys.exit(1)

    # 收集日志文件
    log_files = []
    for d in dirs:
        if os.path.isfile(d):
            log_files.append(d)
            continue
        for root, _, files in os.walk(d):
            for fn in files:
                if fn.endswith(('.log', '.txt')) and 'log' in root.lower() or fn.startswith('console-'):
                    log_files.append(os.path.join(root, fn))
    # 去重 + 排序
    log_files = sorted(set(log_files))
    print(f"发现 {len(log_files)} 个日志文件")

    keys = list(dict.fromkeys([DEFAULT_KEY] + EXTRA_KEYS))
    print(f"尝试密钥: {keys}")

    all_hits = []
    for p in log_files:
        sz = os.path.getsize(p)
        print(f"\n扫描: {p}  ({sz:,} B)")
        hits = scan_file(p, keys, None)
        if hits:
            print(f"  ★ 发现 {len(hits)} 个坐标泄露!")
            for h in hits:
                print(f"    [{h['time']}] {h['sender']}  ->  {h['plaintext']}  (key={h['key']!r})")
            all_hits.extend(hits)
        else:
            print(f"  无")

    # 汇总
    print("\n" + "=" * 70)
    if all_hits:
        print(f"  ★★★ 共发现 {len(all_hits)} 条坐标泄露 ★★★")
        print("=" * 70)
        for h in all_hits:
            print(f"\n  时间:   {h['time']}")
            print(f"  发送者: {h['sender']}")
            print(f"  明文:   {h['plaintext']}")
            print(f"  密钥:   {h['key']!r}")
            # 解析坐标
            mm = re.search(r'EnemyHere\{([^}]*)\}', h['plaintext'])
            if mm:
                parts = mm.group(1).split(',')
                if len(parts) >= 3:
                    try:
                        x, y, z = parts[0], parts[1], parts[2]
                        extra = f", color={parts[3]}" if len(parts) > 3 else ""
                        print(f"  坐标:   ({x}, {y}, {z}){extra}")
                    except Exception:
                        pass
        with open('zenith_ping2_hits.json', 'w', encoding='utf-8') as f:
            json.dump(all_hits, f, ensure_ascii=False, indent=2)
        print(f"\n  结果已保存: zenith_ping2_hits.json")
    else:
        print("  未发现泄露的坐标")
        print("=" * 70)
        print("""
  可能原因：
  1. 日志中没有人使用 Ping2 功能
  2. 使用者的 EncryptKey 不是默认值
  3. 日志早于该功能使用时间
  4. 日志中聊天内容被截断/加密存储
  5. 其他不常见密钥
""")


if __name__ == '__main__':
    main()
