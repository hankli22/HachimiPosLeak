# HachimiPosLeak

> **Security research**: analysis of a coordinate-leak vulnerability in the
> Hachimi Minecraft client (`Ping2` module), and a log scanner that can
> verify the vulnerability against your own server logs.

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## ⚠️ Disclaimer / 免责声明

**This repository is a security research project. / 本项目属于安全研究。**

- ✅ **Only** scan logs that **you own** or have **explicit written permission** to access.
- ❌ **Never** use this to access another person's server logs or private data.
- 📄 **No real player data** is included in this repository. All example output uses synthetic values (`PlayerA`, `PlayerB`, fake coordinates).
- 🔬 The vulnerability was discovered by **static analysis** of a decompiled client (`OpenHachimi`), not by attacking any server.
- ⚖️ Users are solely responsible for complying with applicable laws and the terms of service of any server they operate or use.

**本工具仅供扫描你自己拥有或已获授权的服务器日志。严禁用于访问他人数据。**

**如你是客户端作者并希望修复此问题，见 [Responsible Disclosure](#responsible-disclosure--负责任披露)。**

---

## 摘要 / TL;DR

The **Hachimi** Minecraft cheat client ships a module called **`Ping2`**
(display name `Ping`, description *"Mark points for your friends"*).

It lets a player **ping a block position** which is then encrypted and sent
**through public chat** so that friends can see the marker.

Two design flaws make this a **coordinate leak**:

1. **Hardcoded default encryption key** — `IDKWTFTHIS` (`Ping2.java:360-362`)
2. **Public chat transport** — the ciphertext is broadcast to the whole server
   and persisted in server logs

Because the key is a constant in the bytecode, **anyone who can read the
server chat log can decrypt every pinged coordinate** — no key exchange,
no server access, no privileged position required.

This repository contains a scanner that:

- reads ZenithProxy `.log` / `.txt` / `.tmp` / `.zip` archives,
- finds Base64 chat payloads,
- attempts AES decryption with the default key (and common variants),
- reports any recovered `EnemyHere{x,y,z,color}` messages,
- clusters recovered points to highlight likely bases.

> **No live server data is distributed here.** The tool is provided so server
> operators can audit their own logs and understand their exposure.

---

## 漏洞技术细节 / Technical Details

### 客户端模块

Source: `pw/hachimi/client/module/misc/Ping2.java` (reconstructed from
`OpenHachimi`, a decompilation of the protected `Hachimi-V2-crack.jar`).

```java
public class Ping2 extends ClientModule {
    Setting Sound     = new BooleanSetting("Sound", "When someone ping play sound", true);
    Setting ExistTime = new NumberSetting("ExistTime", "Existence time for mark", 0.0F, 10.0F, 100.0F);
    Setting Color     = new ColorSetting("Color", "color", ...);

    public Ping2() {
        super("Ping", "Mark points for your friends", ModuleCategory.MISC);
        Setting encryptKey = createStringSetting("EncryptKey", "");       // default: IDKWTFTHIS
        Setting pingKey    = new KeybindSetting("Ping", "Ping key", ...); // unbound by default
    }
}
```

### 发送路径

```java
public void Lw() {                                        // keybind callback
    if (this.awg()) {                                     // module enabled
        HitResult hit = client.getCameraEntity()
            .raycast(256.0, 0.0F, false);                 // 256-block ray
        if (hit instanceof BlockHitResult) {
            BlockPos pos = ((BlockHitResult) hit).getBlockPos();
            String cipher = this.LC("EnemyHere{" + x + "," + y + "," + z + "," + color + "}");
            client.getNetworkHandler().sendChatMessage(cipher);   // PUBLIC CHAT
        }
    }
}
```

### 加密实现

```java
// Ping2.java — encrypter (LC) and decrypter (LB) share the same scheme
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
SecretKeySpec key = new SecretKeySpec(
        Arrays.copyOf(MessageDigest.getInstance("SHA-256")
                .digest(encryptKey.getBytes(UTF_8)), 16), "AES");   // AES-128
IvParameterSpec iv = new IvParameterSpec(new byte[16]);             // ALL-ZERO IV
cipher.init(Cipher.ENCRYPT_MODE, key, iv);
return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes(UTF_8)));
```

### 默认密钥

```java
private static StringSetting createStringSetting(String name, String desc) {
    return new StringSetting(name, desc, "IDKWTFTHIS");   // ← hardcoded default
}
```

Derived AES key: `SHA-256("IDKWTFTHIS")[0:16]` =
`e403c0c0e469dcfacc6bb61e32fb1b4d`

### 问题清单 / Issues

| # | Issue | Impact |
|---|---|---|
| 1 | Hardcoded default key in bytecode | Anyone can decrypt |
| 2 | Public-chat transport | Broadcast + persisted in logs |
| 3 | All-zero IV (CBC) | Deterministic ciphertext (equality leaks) |
| 4 | No MAC / integrity check | Ciphertext is malleable |
| 5 | No sender authentication on receive | Anyone can forge `EnemyHere{...}` markers |

### 数据格式

```text
New format (4 values):  EnemyHere{x,y,z,color}
Old format (3 values):  EnemyHere{x,y,z}
```

The ciphertext is Base64-encoded and sent as a normal chat message, e.g.:

```text
[timestamp] [Chat] [INFO] «PlayerA» <Base64 ciphertext>
```

---

## 扫描器 / Scanner

### 依赖

```bash
py -3 -m pip install pycryptodome
```

### 用法

```bash
# Scan default locations (auto-detects common ZenithProxy installs)
py -3 zenith_ping2_scanner.py

# Scan specific directories (local and/or UNC/SMB paths)
py -3 zenith_ping2_scanner.py "C:\servers\ZenithProxy"
py -3 zenith_ping2_scanner.py "\\server\share\ZenithProxy\logs"

# Multiple roots
py -3 zenith_ping2_scanner.py "C:\a" "D:\b"

# Custom keys (merged with the built-in list)
py -3 zenith_ping2_scanner.py --keys IDKWTFTHIS my_key

# Custom output prefix
py -3 zenith_ping2_scanner.py --out audit_2026
```

### 参数

```text
usage: zenith_ping2_scanner.py [roots...] [options]

positional arguments:
  roots                  directories to scan (UNC paths supported)

options:
  --roots ...            same as positional
  --keys ...             additional candidate keys
  --out PREFIX           output prefix (default: zenith_ping2_result)
  -h, --help             show help
```

### 输出示例（合成数据 / synthetic only）

```text
==================================================================
  ZenithProxy Ping2 coordinate leak scanner
==================================================================
  Scanning 335 log files (.log/.txt/.tmp/.zip)

  ★ ...\proxy-2026-01-01.0.log.zip  (+2)

==================================================================
  Summary
==================================================================
  unique messages:  2
  unique players:   2
  points:           2
  clusters:         1

  ── Players ──
    PlayerA                       1
    PlayerB                       1

  ── Clusters (radius 5000) ──
    Region 1: center (1234, -5678)  2 points  players: PlayerA, PlayerB
      [2026/01/01 00:00:00] PlayerA: (1000, 64, -2000)
      [2026/01/01 00:00:01] PlayerB: (1200, -63, -3000)
```

### 输出文件

| File | Content |
|---|---|
| `<prefix>.json` | Structured results (players / points / clusters / source locations) |
| `<prefix>.md` | Human-readable Markdown report |

---

## 支持的日志格式

ZenithProxy chat log lines:

```text
[YYYY/MM/DD HH:MM:SS] [Chat] [INFO] «player» message
[YYYY/MM/DD HH:MM:SS] [Chat] [INFO] «[unknown player head]player» message
```

Supported file types: `.log`, `.txt`, `.tmp`, `.zip` (daily archives are
decompressed in memory — no extraction to disk).

---

## 防御建议 / Mitigation

### 对客户端作者

1. Remove the default key — force per-install random keys.
2. Use a random IV per message (not all-zero).
3. Add a MAC (e.g. HMAC-SHA256) for integrity.
4. Do not transport coordinates through public chat — use a private channel
   or accept only explicit `/msg` sharing.
5. Authenticate the sender on receive.

### 对服务器管理员

1. Filter or rate-limit long Base64 strings in chat.
2. Warn players using the default key.
3. Consider logging chat only where necessary (privacy).

### 对玩家

1. **Change `EncryptKey`** to a non-default value.
2. Prefer not to use `Ping2` over public chat.
3. Remember: anything sent to public chat is logged.

---

## Repository Layout

```text
.
├── README.md
├── LICENSE
├── requirements.txt
├── zenith_ping2_scanner.py          # ★ main scanner (recommended)
├── legacy/
│   ├── scan_zenith_ping2.py         # v1 — basic
│   ├── scan_zenith_ping2_wide.py    # v2 — any decryptable payload
│   └── scan_zenith_ping2_all.py     # v3 — zip archive support
└── extras/
    ├── scan_src.py                  # Java source security scanner (separate use)
    ├── ping2_crypto_demo.py         # key derivation demo
    ├── extract_raw_log_lines.py     # extract raw log lines
    └── final_report.py              # result aggregation / clustering
```

---

## Responsible Disclosure / 负责任披露

If you are the **Hachimi** client author and want to fix this issue:

- The root cause is the default `EncryptKey` (`IDKWTFTHIS`) and the use of
  public chat as transport.
- Recommended fix: remove default keys, use random IVs, add MACs, and move
  coordinate sharing off public chat.

To contact: open an issue in this repository (no real player data is included,
and none will be requested).

**Please do not use this repository to harass players. Security research
should reduce harm, not increase it.**

---

## FAQ

**Q: Does this repository contain real player coordinates?**
No. All examples use synthetic values. The scanner never uploads anything.

**Q: Is it legal to scan my own server logs?**
In most jurisdictions, yes — you own the logs. Always check your local laws
and the terms of your server community.

**Q: Why the default key?**
It's a hardcoded constant in the client bytecode. This is the vulnerability.

**Q: Why do I get no results?**
No one used `Ping2`, or users changed their keys, or the logs don't cover
the relevant period.

---

## License

MIT — see [LICENSE](LICENSE).

---

*This project is published for defensive security research.*
*Use responsibly.*
