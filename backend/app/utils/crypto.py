"""加密工具模块 — 机器绑定密钥派生 + AES-256-GCM

安全设计:
  - 双因子: .env 中的 ENCRYPT_KEY + /etc/machine-id → PBKDF2 派生 AES 密钥
  - 数据库泄露: 无密钥无法解密
  - .env 泄露: 无 machine-id 无法解密
  - 数据库+.env 拷到其他机器: machine-id 不同，无法解密
  - PBKDF2 60万次迭代，暴力破解成本极高
"""

import base64
import ctypes
import logging
import os
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)

# ─── 固定盐（与 machine-id 一起参与密钥派生，提供额外唯一性） ───
_SALT_PREFIX = b"netguard_encryption_salt_v1"
_PBKDF2_ITERATIONS = 600_000  # OWASP 2023 推荐 >= 600k
_KEY_LENGTH = 32  # AES-256


def _get_machine_id() -> str:
    """读取 /etc/machine-id 作为机器绑定因子

    Returns:
        machine-id 字符串，读取失败返回空串
    """
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"]:
        try:
            return Path(path).read_text().strip()
        except (OSError, PermissionError):
            continue
    logger.warning("无法读取 machine-id，加密密钥将不绑定机器")
    return ""


def _derive_key(encryption_key: str) -> bytes:
    """从 ENCRYPT_KEY + machine-id 派生 AES-256 密钥

    Args:
        encryption_key: .env 中的 ENCRYPT_KEY（hex 格式）

    Returns:
        32 字节 AES-256 密钥
    """
    machine_id = _get_machine_id()
    salt = _SALT_PREFIX + machine_id.encode("utf-8")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_LENGTH,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return kdf.derive(encryption_key.encode("utf-8"))


def encrypt(plaintext: str, encryption_key: str) -> str:
    """AES-256-GCM 加密

    Args:
        plaintext: 明文字符串
        encryption_key: .env 中的 ENCRYPT_KEY

    Returns:
        base64 编码的密文 (格式: IV[12] + ciphertext + tag[16])
    """
    key = _derive_key(encryption_key)
    iv = os.urandom(12)  # GCM 推荐 12 字节 IV
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
    # ciphertext 已包含 16 字节 auth tag
    return base64.b64encode(iv + ciphertext).decode("ascii")


def decrypt(ciphertext_b64: str, encryption_key: str) -> str:
    """AES-256-GCM 解密

    Args:
        ciphertext_b64: base64 编码的密文
        encryption_key: .env 中的 ENCRYPT_KEY

    Returns:
        明文字符串

    Raises:
        ValueError: 解密失败（密钥错误或数据损坏）
    """
    try:
        key = _derive_key(encryption_key)
        raw = base64.b64decode(ciphertext_b64)
        iv = raw[:12]
        ciphertext = raw[12:]
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
        return plaintext.decode("utf-8")
    except Exception as e:
        raise ValueError(f"解密失败（密钥错误或数据损坏）: {e}") from e


def clear_memory(data: str | bytes):
    """尽可能清零内存中的敏感数据

    注意: Python 字符串是不可变对象，此方法不能保证完全清除，
    但可减少敏感数据在内存中的驻留时间。
    对于 bytes 对象，使用 ctypes.memset 覆写为 0。
    """
    if isinstance(data, bytes):
        buf_size = len(data)
        if buf_size > 0:
            ctypes.memset(id(data) + 0, 0, buf_size)
    # Python str 是不可变的，无法安全覆写
    # 最佳实践: 使用后尽快让变量超出作用域，便于 GC 回收


def generate_encryption_key() -> str:
    """生成 32 字节随机 hex 字符串，用作 ENCRYPT_KEY"""
    return os.urandom(32).hex()
