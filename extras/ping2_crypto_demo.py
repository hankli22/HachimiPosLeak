import hashlib, base64

print("="*70)
print("  Ping2.java AES 密钥分析")
print("="*70)

# 默认密钥
default_key = "IDKWTFTHIS"
print(f"\n默认 EncryptKey 字符串: {default_key!r}")
print(f"字节长度: {len(default_key.encode('utf-8'))}")

# SHA-256 派生
sha = hashlib.sha256(default_key.encode('utf-8')).digest()
aes_key = sha[:16]
print(f"\nSHA-256({default_key!r}) = {sha.hex()}")
print(f"AES-128 密钥（前16字节）= {aes_key.hex()}")
print(f"AES-128 密钥（Base64）    = {base64.b64encode(aes_key).decode()}")

print("\n" + "="*70)
print("  Java 等价代码验证")
print("="*70)
print(f"""
// Java 里实际执行的是：
byte[] sha = MessageDigest.getInstance("SHA-256")
                       .digest("{default_key}".getBytes(UTF_8));
SecretKeySpec key = new SecretKeySpec(
    Arrays.copyOf(sha, 16), "AES");   // = {aes_key.hex()}
IvParameterSpec iv = new IvParameterSpec(new byte[16]);  // 全零
Cipher.getInstance("AES/CBC/PKCS5Padding")
""")

print("="*70)
print("  攻击者解密流程（伪代码）")
print("="*70)
print(f"""
import hashlib, base64
from Crypto.Cipher import AES

key = hashlib.sha256(b"IDKWTFTHIS").digest()[:16]   # = {aes_key.hex()}
iv  = b"\\x00" * 16                                   # 全零 IV

# 服务器聊天里看到的 Base64 密文
ciphertext = base64.b64decode("...Base64...")
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)
# PKCS5 去填充后得到：EnemyHere{{x}},{{y}},{{z}},{{color}}
""")

print("="*70)
print("  结论")
print("="*70)
print("""
1. 默认密钥 "IDKWTFTHIS" 硬编码在 Ping2.java:361
2. 密钥派生 = SHA-256(字符串)[0:16] → AES-128
3. IV = 全零（固定）
4. 模式 = AES/CBC/PKCS5Padding
5. 密文经 Base64 编码后发到【公共聊天】

=> 任何人不改默认密钥 => 坐标对全服务器公开
""")