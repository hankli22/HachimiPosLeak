#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  zenith_ping2_scanner.py — ZenithProxy 日志中 hachimi Ping2 坐标泄露扫描器
================================================================================

原理
----
hachimi 客户端 Ping2 模块（pw/hachimi/client/module/misc/Ping2.java）：
  1. 按 Ping 键 → 摄像机射线 256 格 → 得到方块坐标
  2. 构造明文  "EnemyHere{x,y,z,color}"
  3. AES-128-CBC 加密（密钥 = SHA-256(EncryptKey)[0:16]，IV = 全零）
  4. Base64 编码
  5. 通过 sendChatMessage() 发到【公共聊天】

默认 EncryptKey = "IDKWTFTHIS"（Ping2.java:360-362）
→ 玩家不改默认密钥 → 坐标可被任何人解密

功能
----
  * 递归扫描 .log / .txt / .tmp / .zip（本地 + SMB/UNC 路径）
  * 多密钥尝试（默认 IDKWTFTHIS + 常见弱密钥）
  * 自动识别 `«sender»` / `<sender>` / `sender>` 聊天格式
  * 规范化发送者名（去掉 `[unknown player head]` 等前缀）
  * 坐标聚类（<5000 格算同区域）
  * 输出 JSON + Markdown 报告

用法
----
  # 1. 扫描默认路径（自动探测常见 ZenithProxy 安装）
  py -3 zenith_ping2_scanner.py

  # 2. 扫描指定目录（可多个，支持 UNC/SMB 路径）
  py -3 zenith_ping2_scanner.py "D:\\ZenithProxy\\logs" "\\\\server\\share\\logs"

  # 3. 自定义密钥 + 输出
  py -3 zenith_ping2_scanner.py --roots LOG_DIR --keys IDKWTFTHIS mykey --out result

依赖
----
  py -3 -m pip install pycryptodome

================================================================================
"""
import os
import re
import sys
import json
import zipfile
import io
import hashlib
import base64
import argparse
from collections import defaultdict

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
except ImportError:
    print("[-] 缺少 pycryptodome，请先运行: py -3 -m pip install pycryptodome")
    sys.exit(1)

# ─────────────────────────── 常量 ───────────────────────────
DEFAULT_KEYS = [
    "IDKWTFTHIS",      # Ping2.java:361 默认值
    "",                # 空字符串
    "hachimi", "Hachimi", "hachimiclient", "hachimi2.0", "Hachimi2.0",
    "123456", "password", "idkwtfthis",
]

# Minecraft 颜色码
COLOR_RE = re.compile(r'§[0-9a-fk-orA-FK-OR]')

# 聊天行： [2026/11/01 00:00:00] [Chat] [INFO] «sender» message
CHAT_RE = re.compile(r'\[(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\] \[Chat\] \[INFO\] (.*)$')

# Base64 token（AES 块至少 16 字节 → Base64 至少 24 字符，但留余量）
B64_RE = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

# 目标明文
TARGET = "EnemyHere"
TARGET_RE = re.compile(r'EnemyHere\s*\{([^}]*)\}')

# 发送者前缀（ZenithProxy 对无法解析皮肤的玩家会加 [unknown player head]）
SENDER_PREFIX_RE = re.compile(r'^\[unknown player head\]', re.I)

# 聚类阈值（方块）
CLUSTER_RADIUS = 5000


# ─────────────────────────── 工具函数 ───────────────────────────
def derive_key(s: str) -> bytes:
    """Ping2.Lu() 等价实现：SHA-256(s)[0:16] → AES-128 密钥"""
    return hashlib.sha256(s.encode('utf-8')).digest()[:16]


def is_printable_ratio(s: str, threshold: float = 0.85) -> bool:
    if not s:
        return False
    ok = sum(1 for c in s if 32 <= ord(c) < 127 or c in '\n\r\t')
    return ok / len(s) >= threshold


def try_decrypt(token: str, keys):
    """尝试用各密钥解密 Base64 token，返回 (plaintext, key) 或 None"""
    try:
        raw = base64.b64decode(token, validate=True)
    except Exception:
        return None
    if not raw or len(raw) % 16 != 0:
        return None
    for k in keys:
        try:
            cipher = AES.new(derive_key(k), AES.MODE_CBC, b'\x00' * 16)
            pt = unpad(cipher.decrypt(raw), 16)
            s = pt.decode('utf-8', errors='replace')
            if is_printable_ratio(s) and len(s) >= 4:
                return s, k
        except Exception:
            continue
    return None


def normalize_sender(s: str) -> str:
    return SENDER_PREFIX_RE.sub('', s).strip()


def parse_sender(clean: str):
    """从聊天正文解析发送者，返回 (sender, message)"""
    m = re.match(r'[«<]([^»>]+)[»>]\s*(.*)$', clean)
    if m:
        return m.group(1), m.group(2)
    m2 = re.match(r'([A-Za-z0-9_|]{3,24})\s*[»>]\s*(.*)$', clean)
    if m2:
        return m2.group(1), m2.group(2)
    return '?', clean


# ─────────────────────────── 扫描核心 ───────────────────────────
def scan_lines(iterable, keys, src_name, hits):
    """扫描一个文本行迭代器"""
    for lineno, line in enumerate(iterable, 1):
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
                plaintext, used_key = r
                hits.append({
                    'source': src_name,
                    'line': lineno,
                    'time': ts,
                    'sender': normalize_sender(sender),
                    'plaintext': plaintext,
                    'key': used_key,
                    'token': tok,
                })


def scan_plain_file(path, keys, hits):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            scan_lines(f, keys, os.path.basename(path), hits)
    except Exception as e:
        print(f"    [跳过] {path}: {e}")


def scan_zip_file(path, keys, hits):
    try:
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if not name.endswith(('.log', '.txt')):
                    continue
                with z.open(name) as f:
                    text = io.TextIOWrapper(f, encoding='utf-8', errors='replace')
                    scan_lines(text, keys, f"{os.path.basename(path)}:{name}", hits)
    except Exception as e:
        print(f"    [跳过] {path}: {e}")


def collect_files(roots):
    """收集所有待扫描文件，返回 [(path, kind)]"""
    files = []
    for root in roots:
        if not os.path.isdir(root):
            if os.path.isfile(root):
                files.append((root, 'plain'))
            continue
        for dp, _, fns in os.walk(root):
            for fn in fns:
                p = os.path.join(dp, fn)
                low = fn.lower()
                if low.endswith(('.log', '.txt', '.tmp')):
                    files.append((p, 'plain'))
                elif low.endswith('.zip') and 'log' in dp.lower():
                    files.append((p, 'zip'))
    # 去重并排序
    return sorted(set(files))


def extract_coords(plaintext):
    """从明文提取 (x, y, z) 或 None"""
    m = TARGET_RE.search(plaintext)
    if not m:
        return None
    parts = m.group(1).split(',')
    if len(parts) < 3:
        return None
    try:
        return int(parts[0]), int(parts[1]), int(parts[2]), (parts[3] if len(parts) > 3 else None)
    except ValueError:
        return None


def cluster_points(points, radius=CLUSTER_RADIUS):
    """简单聚类：欧氏距离（水平面）< radius 算同区域"""
    clusters = []
    for p in points:
        placed = False
        for cl in clusters:
            cx, cz = cl[0]['x'], cl[0]['z']
            if abs(p['x'] - cx) <= radius and abs(p['z'] - cz) <= radius:
                cl.append(p)
                placed = True
                break
        if not placed:
            clusters.append([p])
    return clusters


# ─────────────────────────── 报告 ───────────────────────────
def build_report(hits):
    uniq = {}
    for h in hits:
        k = (h['time'], h['sender'], h['plaintext'])
        uniq[k] = h
    rows = sorted(uniq.values(), key=lambda x: (x['sender'], x['time']))

    points = []
    for r in rows:
        c = extract_coords(r['plaintext'])
        if c:
            points.append({'sender': r['sender'], 'time': r['time'],
                           'x': c[0], 'y': c[1], 'z': c[2], 'color': c[3]})

    clusters = cluster_points(points)
    players = sorted(set(r['sender'] for r in rows))
    return rows, points, clusters, players


def print_report(rows, points, clusters, players):
    bar = "=" * 78
    print(f"\n{bar}")
    print(f"  结果汇总")
    print(bar)
    print(f"  唯一消息:   {len(rows)}")
    print(f"  唯一玩家:   {len(players)}")
    print(f"  坐标点数:   {len(points)}")
    print(f"  聚类区域:   {len(clusters)}")

    print(f"\n  ── 玩家列表 ──")
    by_sender = defaultdict(list)
    for r in rows:
        by_sender[r['sender']].append(r)
    for sender in sorted(by_sender):
        print(f"    {sender:<30} {len(by_sender[sender])} 条")
    print(f"\n  ── 按玩家详情 ──")
    for sender in sorted(by_sender):
        print(f"\n  ┌─ {sender}")
        for r in sorted(by_sender[sender], key=lambda x: x['time']):
            c = extract_coords(r['plaintext'])
            coord = f"({c[0]}, {c[1]}, {c[2]})" if c else r['plaintext']
            fmt = '新' if c and c[3] is not None else '旧'
            print(f"  │ [{r['time']}] {coord}  ({fmt}格式)")
        print(f"  └{'─' * 60}")

    if clusters:
        print(f"\n  ── 坐标聚类（半径 {CLUSTER_RADIUS} 格）──")
        for i, cl in enumerate(sorted(clusters, key=lambda x: -len(x)), 1):
            xs = [p['x'] for p in cl]
            zs = [p['z'] for p in cl]
            cx, cz = sum(xs) // len(xs), sum(zs) // len(zs)
            pl = sorted(set(p['sender'] for p in cl))
            print(f"\n    区域 {i}: 中心 ({cx}, {cz})  {len(cl)} 条  玩家: {', '.join(pl)}")
            for p in sorted(cl, key=lambda x: x['time']):
                print(f"      [{p['time']}] {p['sender']}: ({p['x']}, {p['y']}, {p['z']})")


def save_outputs(rows, points, clusters, players, out_prefix):
    data = {
        'unique_players': players,
        'unique_messages': len(rows),
        'points': points,
        'leaks': [{'sender': r['sender'], 'time': r['time'],
                   'plaintext': r['plaintext'], 'key': r['key'],
                   'source': r['source'], 'line': r['line']} for r in rows],
        'clusters': [{
            'center': (sum(p['x'] for p in cl) // len(cl), sum(p['z'] for p in cl) // len(cl)),
            'count': len(cl),
            'players': sorted(set(p['sender'] for p in cl)),
            'points': [{'x': p['x'], 'y': p['y'], 'z': p['z'], 'sender': p['sender'], 'time': p['time']} for p in cl],
        } for cl in clusters],
    }
    json_path = out_prefix + '.json'
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"\n  [OK] JSON: {json_path}")

    # Markdown
    md = [f"# ZenithProxy Ping2 坐标泄露报告", "",
          f"- 唯一消息: {len(rows)}",
          f"- 唯一玩家: {len(players)}",
          f"- 坐标点数: {len(points)}",
          f"- 聚类区域: {len(clusters)}", "", "## 玩家列表", ""]
    for s in players:
        md.append(f"- `{s}`")
    md += ["", "## 泄露坐标", "", "| 玩家 | 时间 | 坐标 | 来源 |", "|---|---|---|---|"]
    for p in points:
        md.append(f"| `{p['sender']}` | {p['time']} | ({p['x']}, {p['y']}, {p['z']}) | - |")
    md += ["", "## 聚类区域", ""]
    for i, cl in enumerate(sorted(clusters, key=lambda x: -len(x)), 1):
        cx = sum(p['x'] for p in cl) // len(cl)
        cz = sum(p['z'] for p in cl) // len(cl)
        pl = sorted(set(p['sender'] for p in cl))
        md.append(f"### 区域 {i}: 中心 ({cx}, {cz})")
        md.append(f"- 玩家: {', '.join(pl)}")
        for p in sorted(cl, key=lambda x: x['time']):
            md.append(f"- [{p['time']}] `{p['sender']}` ({p['x']}, {p['y']}, {p['z']})")
        md.append("")
    md_path = out_prefix + '.md'
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(md))
    print(f"  [OK] MD:   {md_path}")


# ─────────────────────────── 主程序 ───────────────────────────
def default_roots():
    """自动探测常见 ZenithProxy 安装位置"""
    candidates = [
        os.path.expanduser(r'~\Desktop\servers\ZenithProxy'),
        os.path.expanduser(r'~\Desktop\ZenithProxy'),
        r'D:\minecraft\ZenithProxy',
        r'C:\ZenithProxy',
        r'D:\ZenithProxy',
    ]
    return [c for c in candidates if os.path.isdir(c)]


def main():
    ap = argparse.ArgumentParser(description='ZenithProxy 日志 hachimi Ping2 坐标泄露扫描器')
    ap.add_argument('roots', nargs='*', help='扫描目录（默认自动探测）')
    ap.add_argument('--roots', dest='roots_opt', nargs='*', help='同位置参数')
    ap.add_argument('--keys', nargs='*', default=None, help='自定义密钥（会与默认密钥合并）')
    ap.add_argument('--out', default='zenith_ping2_result', help='输出文件前缀')
    args = ap.parse_args()

    roots = args.roots + (args.roots_opt or [])
    if not roots:
        roots = default_roots()
    if not roots:
        print("[-] 未找到 ZenithProxy 目录，请手动指定: py -3 zenith_ping2_scanner.py <目录>")
        sys.exit(1)

    keys = DEFAULT_KEYS[:]
    if args.keys:
        keys = list(dict.fromkeys(args.keys + keys))

    print("=" * 78)
    print("  ZenithProxy Ping2 坐标泄露扫描器")
    print("=" * 78)
    print(f"  扫描目录 ({len(roots)}):")
    for r in roots:
        print(f"    - {r}")
    print(f"  尝试密钥 ({len(keys)}): {keys}")

    files = collect_files(roots)
    print(f"\n  发现 {len(files)} 个日志文件（.log/.txt/.tmp/.zip）\n")

    hits = []
    scanned = 0
    for p, kind in files:
        scanned += 1
        if scanned % 50 == 0:
            print(f"  ... 已扫描 {scanned}/{len(files)}，累计命中 {len(hits)}")
        before = len(hits)
        if kind == 'zip':
            scan_zip_file(p, keys, hits)
        else:
            scan_plain_file(p, keys, hits)
        if len(hits) > before:
            print(f"  ★ {p}  (+{len(hits) - before})")

    if not hits:
        print("\n  未发现任何可解密的 Ping2 坐标。")
        print("  可能原因：无人使用 Ping2 / 玩家已改密钥 / 日志不含该时段")
        return

    rows, points, clusters, players = build_report(hits)
    print_report(rows, points, clusters, players)
    save_outputs(rows, points, clusters, players, args.out)


if __name__ == '__main__':
    main()
