#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scan_zenith_ping2_wide.py -- 扩大扫描：任何能用默认密钥解密的 Base64
"""
import os, re, sys, hashlib, base64, json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

DEFAULT_KEY = "IDKWTFTHIS"
EXTRA_KEYS = ["", "hachimi", "Hachimi", "hachimiclient", "123456", "password",
              "idkwtfthis", "hachimi123", "hachimi2.0", "Hachimi2.0"]
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
            # 只接受可打印比例高的结果
            printable = sum(1 for c in s if 32 <= ord(c) < 127 or c in '\n\r\t')
            if printable / max(len(s), 1) > 0.85 and len(s) >= 4:
                return s, k
        except Exception:
            continue
    return None


def parse_sender(clean):
    m = re.match(r'[«<]([^»>]+)[»>]\s*(.*)$', clean)
    if m:
        return m.group(1), m.group(2)
    m2 = re.match(r'([A-Za-z0-9_|]{3,20})\s*[»>]\s*(.*)$', clean)
    if m2:
        return m2.group(1), m2.group(2)
    return '?', clean


def scan_file(path, keys):
    hits = []
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for lineno, line in enumerate(f, 1):
                line = line.rstrip('\n')
                m = CHAT_RE.search(line)
                if not m:
                    continue
                ts, body = m.group(1), m.group(2)
                clean = COLOR_RE.sub('', body)
                sender, msg = parse_sender(clean)
                for tok in B64_RE.findall(msg):
                    r = try_decrypt(tok, keys)
                    if r:
                        hits.append({'file': path, 'line': lineno, 'time': ts,
                                     'sender': sender, 'plaintext': r[0], 'key': r[1],
                                     'token': tok})
    except Exception as e:
        print(f"  [err] {path}: {e}")
    return hits


def main():
    roots = sys.argv[1:] or [r'C:\Users\Administrator\Desktop\servers\ZenithProxy',
                             r'D:\minecraft\ZenithProxy']
    log_files = set()
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dp, _, fns in os.walk(root):
            for fn in fns:
                if fn.endswith(('.log', '.txt', '.log.gz', '.txt.gz')):
                    log_files.add(os.path.join(dp, fn))
    log_files = sorted(log_files)
    print(f"扫描 {len(log_files)} 个文件")
    keys = list(dict.fromkeys([DEFAULT_KEY] + EXTRA_KEYS))
    all_hits = []
    for p in log_files:
        hits = scan_file(p, keys)
        if hits:
            print(f"\n★ {p}  ({os.path.getsize(p):,} B)")
            for h in hits:
                print(f"   [{h['time']}] {h['sender']}: {h['plaintext']!r}  (key={h['key']!r})")
            all_hits.extend(hits)

    print("\n" + "=" * 72)
    print(f"  共 {len(all_hits)} 条可解密消息")
    print("=" * 72)
    # 去重（按 明文+时间+发送者）
    uniq = {}
    for h in all_hits:
        k = (h['time'], h['sender'], h['plaintext'])
        uniq[k] = h
    print(f"  去重后 {len(uniq)} 条")
    for (ts, sender, pt), h in sorted(uniq.items()):
        print(f"\n  [{ts}] {sender}")
        print(f"    明文: {pt}")
        print(f"    密钥: {h['key']!r}")
        print(f"    来源: {os.path.basename(h['file'])}:{h['line']}")
    with open('zenith_ping2_wide.json', 'w', encoding='utf-8') as f:
        json.dump(list(uniq.values()), f, ensure_ascii=False, indent=2)
    print(f"\n  已保存: zenith_ping2_wide.json")


if __name__ == '__main__':
    main()
