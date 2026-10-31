import json, re, os
p = r'D:\mc\隔离区\zenith_ping2_all.json'
data = json.load(open(p, encoding='utf-8'))

def norm(s):
    s = s.replace('[unknown player head]', '')
    return s

by_player = {}
for h in data:
    sender = norm(h['sender'])
    pt = h['plaintext']
    m = re.search(r'EnemyHere\s*\{([^}]*)\}', pt)
    coord = tuple(m.group(1).split(',')) if m else ()
    key = (sender, coord)
    if key not in by_player:
        by_player[key] = h

print("=" * 78)
print("  ZenithProxy Ping2 坐标泄露 — 最终去重清单")
print("=" * 78)
rows = sorted(by_player.values(), key=lambda x: (norm(x['sender']), x['time']))
print(f"\n  唯一 (玩家, 坐标) 组合: {len(rows)}")
print(f"  唯一玩家: {len(set(norm(r['sender']) for r in rows))}\n")

by_sender = {}
for r in rows:
    by_sender.setdefault(norm(r['sender']), []).append(r)

for sender in sorted(by_sender.keys()):
    rs = by_sender[sender]
    print(f"\n  ┌─ {sender}  ({len(rs)} 条)")
    for r in sorted(rs, key=lambda x: x['time']):
        m = re.search(r'EnemyHere\s*\{([^}]*)\}', r['plaintext'])
        if m:
            parts = m.group(1).split(',')
            fmt = '新(4值)' if len(parts) >= 4 else '旧(3值)'
            print(f"  │ {r['time']}  ({parts[0]}, {parts[1]}, {parts[2]})  {fmt}")
    print("  └" + "─" * 50)

# 坐标聚类分析
print("\n" + "=" * 78)
print("  坐标聚类分析（找基地）")
print("=" * 78)
coords = []
for r in rows:
    m = re.search(r'EnemyHere\s*\{([^}]*)\}', r['plaintext'])
    if m:
        parts = m.group(1).split(',')
        try:
            coords.append((norm(r['sender']), r['time'], int(parts[0]), int(parts[1]), int(parts[2])))
        except: pass

# 简单聚类：距离 < 5000 格算同区域
clusters = []
for c in coords:
    placed = False
    for cl in clusters:
        cx, cz = cl[0][2], cl[0][4]
        if abs(c[2]-cx) < 5000 and abs(c[4]-cz) < 5000:
            cl.append(c); placed = True; break
    if not placed:
        clusters.append([c])

print(f"\n  发现 {len(clusters)} 个坐标聚类区域:\n")
for i, cl in enumerate(sorted(clusters, key=lambda x: -len(x)), 1):
    xs = [c[2] for c in cl]; zs = [c[4] for c in cl]
    cx = sum(xs)//len(xs); cz = sum(zs)//len(zs)
    players = sorted(set(c[0] for c in cl))
    print(f"  区域 {i}: 中心约 ({cx}, {cz})  — {len(cl)} 条, 玩家: {', '.join(players)}")
    for c in sorted(cl, key=lambda x: x[1]):
        print(f"      [{c[1]}] {c[0]}: ({c[2]}, {c[3]}, {c[4]})")

# 保存
out = {
    'unique_players': sorted(set(norm(r['sender']) for r in rows)),
    'unique_coords': len(rows),
    'leaks': [{'sender': norm(r['sender']), 'time': r['time'],
               'plaintext': r['plaintext'], 'key': r['key']} for r in rows],
    'clusters': [{'center': (sum(c[2] for c in cl)//len(cl), sum(c[4] for c in cl)//len(cl)),
                  'count': len(cl), 'players': sorted(set(c[0] for c in cl)),
                  'points': [(c[2], c[3], c[4]) for c in cl]} for cl in clusters]
}
json.dump(out, open(r'D:\mc\隔离区\zenith_ping2_FINAL.json', 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
print(f"\n  已保存: D:\\mc\\隔离区\\zenith_ping2_FINAL.json")