#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scan_zenith_ping2_all.py -- 扫描 ZenithProxy 全部日志（含 zip 归档）
"""
import os, re, sys, hashlib, base64, json, zipfile, io

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

DEFAULT_KEY = "IDKWTFTHIS"
EXTRA_KEYS = ["", "hachimi", "Hachimi", "hachimiclient", "123456", "password",
              "idkwtfthis", "hachimi123", "hachimi2.0", "Hachimi2.0", "hachimi2"]
COLOR_RE = re.compile(r'§[0-9a-fk-orA-FK-OR]')
CHAT_RE = re.compile(r'\[(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\] \[Chat\] \[INFO\] (.*)$')
B64_RE = re.compile(r'[A-Za-z0-9+/]{16,}={0,2}')

def derive_key(s):
    return hashlib.sha256(s.encode('utf-8')).digest()[:16]

def try_decrypt(token, keys):
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
            printable = sum(1 for c in s if 32 <= ord(c) < 127 or c in '\n\r\t')
            if printable / max(len(s), 1) > 0.85 and len(s) >= 4:
                return s, k
        except Exception:
            continue
    return None

def parse_sender(clean):
    m = re.match(r'[«<]([^»>]+)[»>]\s*(.*)$', clean)
    if m: return m.group(1), m.group(2)
    m2 = re.match(r'([A-Za-z0-9_|]{3,20})\s*[»>]\s*(.*)$', clean)
    if m2: return m2.group(1), m2.group(2)
    return '?', clean

def scan_lines(iterable, keys, srcname, hits):
    for lineno, line in enumerate(iterable, 1):
        line = line.rstrip('\n')
        m = CHAT_RE.search(line)
        if not m: continue
        ts, body = m.group(1), m.group(2)
        clean = COLOR_RE.sub('', body)
        sender, msg = parse_sender(clean)
        for tok in B64_RE.findall(msg):
            r = try_decrypt(tok, keys)
            if r:
                hits.append({'src': srcname, 'line': lineno, 'time': ts,
                             'sender': sender, 'plaintext': r[0], 'key': r[1]})

def scan_plain(path, keys, hits):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            scan_lines(f, keys, os.path.basename(path), hits)
    except Exception as e:
        print(f"  [err] {path}: {e}")

def scan_zip(path, keys, hits):
    try:
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if not name.endswith(('.log', '.txt')): continue
                with z.open(name) as f:
                    text = io.TextIOWrapper(f, encoding='utf-8', errors='replace')
                    scan_lines(text, keys, f"{os.path.basename(path)}:{name}", hits)
    except Exception as e:
        print(f"  [err] {path}: {e}")

def main():
    roots = sys.argv[1:] or [r'C:\Users\Administrator\Desktop\servers\ZenithProxy',
                             r'D:\minecraft\ZenithProxy']
    files = []
    for root in roots:
        if not os.path.isdir(root): continue
        for dp, _, fns in os.walk(root):
            for fn in fns:
                p = os.path.join(dp, fn)
                if fn.endswith(('.log', '.txt', '.tmp')):
                    files.append((p, 'plain'))
                elif fn.endswith('.zip') and 'log' in dp.lower():
                    files.append((p, 'zip'))
    files = sorted(set(files))
    print(f"扫描 {len(files)} 个日志（文件+归档）")
    keys = list(dict.fromkeys([DEFAULT_KEY] + EXTRA_KEYS))
    hits = []
    for p, kind in files:
        before = len(hits)
        if kind == 'plain':
            scan_plain(p, keys, hits)
        else:
            scan_zip(p, keys, hits)
        if len(hits) > before:
            print(f"  ★ {p}  (+{len(hits)-before})")

    print("\n" + "=" * 74)
    print(f"  共 {len(hits)} 条命中")
    print("=" * 74)
    # 去重
    uniq = {}
    for h in hits:
        uniq[(h['time'], h['sender'], h['plaintext'])] = h
    print(f"  去重后 {len(uniq)} 条\n")

    # 按发送者分组
    by_sender = {}
    for (ts, sender, pt), h in sorted(uniq.items()):
        by_sender.setdefault(sender, []).append((ts, pt, h['src'], h['key']))

    for sender, rows in sorted(by_sender.items()):
        print(f"\n  ┌─ 发送者: {sender}  ({len(rows)} 条)")
        for ts, pt, src, key in rows:
            mm = re.search(r'EnemyHere\{([^}]*)\}', pt)
            coord = ''
            if mm:
                parts = mm.group(1).split(',')
                if len(parts) >= 3:
                    coord = f"  → 坐标 ({parts[0]}, {parts[1]}, {parts[2]})"
            print(f"  │ [{ts}] {pt}{coord}")
            print(f"  │   来源: {src}  key={key!r}")
        print("  └" + "─" * 60)

    with open('zenith_ping2_all.json', 'w', encoding='utf-8') as f:
        json.dump(list(uniq.values()), f, ensure_ascii=False, indent=2)
    print(f"\n  已保存: zenith_ping2_all.json")

if __name__ == '__main__':
    main()
