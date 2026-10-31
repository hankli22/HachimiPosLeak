import zipfile, re
import os

# 在多个日志里找带 "「/«」" 前缀的长 Base64 行
targets = [
    r'C:\Users\Administrator\Desktop\servers\ZenithProxy\hankli22\log\debug.log',
    r'\\100.119.189.127\C$\Users\Administrator\Desktop\ZenithProxy\hankli67\log\proxy-2026-10-22.0.log.zip',
    r'\\100.119.189.127\C$\Users\Administrator\Desktop\ZenithProxy\hankli67\log\proxy-2026-10-23.0.log.zip',
]
pat = re.compile(r'\[(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\] \[Chat\] \[INFO\] (.*)$')
b64 = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')

def scan(text):
    for line in text.splitlines():
        m = pat.search(line)
        if not m:
            continue
        ts, body = m.group(1), m.group(2)
        if b64.search(body):
            yield ts, line

for t in targets:
    if not os.path.exists(t):
        print(f"skip: {t}")
        continue
    print("=" * 70)
    print("FILE:", t)
    if t.endswith('.zip'):
        with zipfile.ZipFile(t) as z:
            for name in z.namelist():
                if not name.endswith(('.log','.txt')):
                    continue
                with z.open(name) as f:
                    text = f.read().decode('utf-8', errors='replace')
                for ts, line in scan(text):
                    print("  ", line[:400])
    else:
        text = open(t, encoding='utf-8', errors='replace').read()
        for ts, line in scan(text):
            print("  ", line[:400])