# ZenithProxy Ping2 坐标泄露扫描器

> 扫描 Minecraft 代理服务器（ZenithProxy）日志，解密 hachimi 客户端 `Ping2` 模块
> 通过公共聊天泄露的玩家坐标。

---

## ⚠️ 免责声明

**本工具仅供：**

- 扫描**你自己拥有**的服务器/代理日志
- 你有**明确授权**的日志
- 安全研究与漏洞验证

**禁止**用于扫描他人服务器、窃取他人隐私。使用者需自行承担法律责任。

---

## 背景

### 漏洞原理

Minecraft 作弊客户端 **Hachimi** 的 `Ping2` 模块（`pw/hachimi/client/module/misc/Ping2.java`）：

```java
// 1. 按 Ping 键 → 摄像机射线 256 格
HitResult hit = camera.raycast(256.0, 0.0F, false);
BlockPos pos = hit.getBlockPos();

// 2. 构造明文
String plaintext = "EnemyHere{" + x + "," + y + "," + z + "," + color + "}";

// 3. AES-128-CBC 加密（密钥 = SHA-256(EncryptKey)[0:16]，IV = 全零）
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
SecretKeySpec key = new SecretKeySpec(sha256(encryptKey).slice(0,16), "AES");
IvParameterSpec iv = new IvParameterSpec(new byte[16]);   // 全零 IV
String encrypted = Base64.encode(cipher.doFinal(plaintext));

// 4. ★ 通过公共聊天发送（不是私聊！）
networkHandler.sendChatMessage(encrypted);
```

### 默认密钥

```java
// Ping2.java:360-362
private static StringSetting createStringSetting(String str, String str2) {
    return new StringSetting(str, str2, "IDKWTFTHIS");   // ← 默认密钥
}
```

**⇒ 如果玩家不修改 `EncryptKey` 设置，所有坐标都可以被任何人解密。**

### 为什么危险

| 问题 | 后果 |
|---|---|
| 消息发在**公共聊天** | 服务器日志永久保存、所有人可见 |
| **默认密钥**写死在源码 | 任何人可解密 |
| **全零 IV** | 相同明文 → 相同密文（确定性加密）|
| 无 MAC/完整性校验 | 密文可篡改 |
| 接收端不验证发送者 | 可伪造坐标标记 |

---

## 安装

```bash
# 1. 安装 Python 3.8+
python --version

# 2. 安装依赖
pip install pycryptodome
# 或
py -3 -m pip install pycryptodome
```

---

## 使用

### 快速开始

```bash
# 自动探测常见 ZenithProxy 安装位置
py -3 zenith_ping2_scanner.py
```

### 指定目录

```bash
# 单个目录
py -3 zenith_ping2_scanner.py "C:\servers\ZenithProxy"

# 多个目录
py -3 zenith_ping2_scanner.py \
  "C:\servers\ZenithProxy\hankli22" \
  "D:\minecraft\ZenithProxy"

# SMB / UNC 网络路径
py -3 zenith_ping2_scanner.py "\\192.168.1.100\C$\ZenithProxy"
```

### 自定义参数

```bash
# 自定义密钥（会与默认密钥合并）
py -3 zenith_ping2_scanner.py --keys IDKWTFTHIS my_custom_key

# 自定义输出前缀
py -3 zenith_ping2_scanner.py --out scan_20261101
```

### 完整参数

```
用法: zenith_ping2_scanner.py [roots...] [options]

位置参数:
  roots                 扫描目录（可多个，支持 UNC 路径）

选项:
  --roots ROOTS [ROOTS ...]   同位置参数
  --keys KEYS [KEYS ...]      自定义密钥（与默认合并）
  --out PREFIX                输出文件前缀（默认 zenith_ping2_result）
  -h, --help                  帮助
```

---

## 输出

### 控制台

```
==================================================================
  ZenithProxy Ping2 坐标泄露扫描器
==================================================================
  扫描目录 (3):
    - \\100.119.189.127\C$\...\ZenithProxy
    - C:\Users\...\servers\ZenithProxy
    - D:\minecraft\ZenithProxy
  尝试密钥 (10): ['IDKWTFTHIS', '', 'hachimi', ...]

  发现 335 个日志文件（.log/.txt/.tmp/.zip）

  ★ ...\proxy-2026-10-23.0.log.zip  (+2)
  ...

==================================================================
  结果汇总
==================================================================
  唯一消息:   20
  唯一玩家:   12
  坐标点数:   20
  聚类区域:   11

  ── 玩家列表 ──
    HHY_1337                       2 条
    ||Fcrestalpvp18                4 条
    ...

  ── 坐标聚类（半径 5000 格）──
    区域 1: 中心 (-4086273, 6782792)  4 条  玩家: ||Fcrestalpvp18
      [2026/10/22 00:17:14] ||Fcrestalpvp18: (-4086199, 67, 6782562)
      ...
```

### 文件

| 文件 | 内容 |
|---|---|
| `<前缀>.json` | 结构化数据（玩家/坐标/聚类/原始来源）|
| `<前缀>.md` | Markdown 格式报告 |

### JSON 结构

```json
{
  "unique_players": ["HHY_1337", "||Fcrestalpvp18", ...],
  "unique_messages": 20,
  "points": [
    {"sender": "||Fcrestalpvp18", "time": "2026/10/22 00:17:14",
     "x": -4086199, "y": 67, "z": 6782562, "color": "2046875110"}
  ],
  "leaks": [
    {"sender": "...", "time": "...", "plaintext": "EnemyHere{...}",
     "key": "IDKWTFTHIS", "source": "proxy-2026-10-22.0.log.zip:...", "line": 100}
  ],
  "clusters": [
    {"center": [-4086273, 6782792], "count": 4,
     "players": ["||Fcrestalpvp18"], "points": [...]}
  ]
}
```

---

## 支持的日志格式

### ZenithProxy 聊天日志

```
[2026/11/01 00:00:00] [Chat] [INFO] «||player» message
[2026/11/01 00:00:00] [Chat] [INFO] «[unknown player head]player» message
[2026/11/01 00:00:00] [Chat] [INFO] «premium_player» message
```

### 支持的加密消息格式

```
新格式（4 值）:  EnemyHere{x,y,z,color}
旧格式（3 值）:  EnemyHere {x,y,z}
```

### 支持的文件

- `.log` — 当前日志
- `.txt` — console 输出
- `.tmp` — 未完成的日志
- `.zip` — 每日归档日志（自动解压内存中扫描）

---

## 脚本结构

```
zenith-ping2-scanner/
├── README.md                        ← 本文档
├── LICENSE                          ← MIT
├── requirements.txt                 ← 依赖
├── zenith_ping2_scanner.py          ← ★ 主脚本（推荐使用）
├── legacy/
│   ├── scan_zenith_ping2.py         ← v1 基础版（无 zip 支持）
│   ├── scan_zenith_ping2_wide.py    ← v2 扩大版（任意可解密内容）
│   └── scan_zenith_ping2_all.py     ← v3 全量版（zip 归档）
└── extras/
    ├── scan_src.py                  ← Java 源码安全扫描器（另一用途）
    ├── ping2_crypto_demo.py         ← 密钥派生演示
    ├── extract_raw_log_lines.py     ← 提取原始日志行
    └── final_report.py              ← 结果统计/聚类
```

---

## 技术细节

### 密钥派生（与 Java 完全一致）

```python
def derive_key(s: str) -> bytes:
    """Ping2.Lu() 等价：SHA-256(s)[0:16]"""
    return hashlib.sha256(s.encode('utf-8')).digest()[:16]
```

### 解密

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

cipher = AES.new(derive_key("IDKWTFTHIS"), AES.MODE_CBC, b'\x00' * 16)
plaintext = unpad(cipher.decrypt(base64.b64decode(token)), 16)
# → "EnemyHere{x,y,z,color}"
```

### 为什么用多密钥尝试

除了默认的 `IDKWTFTHIS`，脚本还会尝试常见弱密钥：

```python
DEFAULT_KEYS = [
    "IDKWTFTHIS",   # Ping2.java:361 默认值
    "",             # 空字符串
    "hachimi", "Hachimi", "hachimiclient",
    "hachimi2.0", "Hachimi2.0",
    "123456", "password", "idkwtfthis",
]
```

---

## 常见问题

### Q: 扫不到任何结果？

可能原因：
1. 日志中没人用 Ping2 功能
2. 使用者修改了 `EncryptKey`
3. 日志早于功能使用时间
4. 日志中聊天内容被截断

### Q: 能不能解密密文但看不到坐标？

如果解出的明文不含 `EnemyHere`，说明是别的加密内容（如皮肤签名）。脚本会过滤。

### Q: 会不会误伤（误报）？

脚本要求：
- 解密后必须是可打印文本（>85% 可打印字符）
- 长度 ≥ 4
- 严格 Base64 校验
- AES 块长度对齐

误报率极低。

### Q: 如何防御？

1. **玩家**：修改 `EncryptKey` 为非默认值
2. **服务器管理员**：
   - 在聊天中过滤 Base64 长串
   - 提醒玩家修改密钥
3. **客户端作者**：
   - 不要用默认密钥
   - 改用私聊/加密通道
   - 使用随机 IV + MAC

---

## 版本

| 版本 | 说明 |
|---|---|
| v1.0.0 | 初始版本（整合 legacy 三个脚本）|

---

## 许可证

MIT License — 见 [LICENSE](LICENSE)

---

## 致谢

- 分析基础：`OpenHachimi` 重建源码（`pw/hachimi/client/module/misc/Ping2.java`）
- 漏洞发现：静态审计 + 实际日志验证

---

**⚠️ 再次强调：仅扫描你自己的服务器日志。**
