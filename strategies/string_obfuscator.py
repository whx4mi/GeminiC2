# string_obfuscator.py
#
# BUILD-TIME: usa os/hashlib/base64 (stdlib puro) para criptografar strings.
# RUNTIME:    rs() usa apenas stdlib — zero dependência de Cryptodome no exe final.
#
# Algoritmo: PBKDF2-HMAC-SHA256(master_key, iv, 1) → keystream → XOR com plaintext.
# Segurança equivalente a AES-CTR para fins de ofuscação: cada string tem IV único,
# o keystream é derivado de uma PRF, e a chave mestra varia a cada build.

import base64
import hashlib
import os


class SessionObfuscator:
    """
    Gerencia a ofuscação para uma única sessão de build.
    Usa apenas stdlib — sem Cryptodome no build nem no runtime do exe.
    """

    def __init__(self):
        self.master_key = os.urandom(32)  # 256-bit key, gerada com CSPRNG do SO

    def get_master_key_b64(self) -> str:
        return base64.b64encode(self.master_key).decode("utf-8")

    def obfuscate(self, original_string: str) -> tuple[str, str]:
        """
        Cifra uma string com PBKDF2-XOR.
        Retorna (encrypted_b64, iv_b64) — mantém a assinatura original (iv primeiro, enc segundo).
        """
        data = original_string.encode("utf-8")
        iv   = os.urandom(16)                          # IV único por string
        # Deriva keystream: PBKDF2(key, iv, iterations=1, len=len(data))
        keystream = hashlib.pbkdf2_hmac("sha256", self.master_key, iv, 1, dklen=len(data))
        encrypted = bytes(a ^ b for a, b in zip(data, keystream))

        iv_b64  = base64.b64encode(iv).decode("utf-8")
        enc_b64 = base64.b64encode(encrypted).decode("utf-8")
        return iv_b64, enc_b64          # (iv_b64, encrypted_b64) — igual à assinatura anterior

    @staticmethod
    def get_decrypt_function_code() -> str:
        """
        Código injetado no agente obfuscado. Usa APENAS stdlib (base64 + hashlib).
        Nenhum import externo → sem risco de ModuleNotFoundError no exe.
        """
        return """
import base64 as _b64
import hashlib as _hl

_DECRYPT_CACHE = {}
_MASTER_KEY = None

def _init_decrypt(key_b64):
    global _MASTER_KEY
    if _MASTER_KEY is None:
        _MASTER_KEY = _b64.b64decode(key_b64)

def rs(enc_str_b64, iv_b64):
    if enc_str_b64 in _DECRYPT_CACHE:
        return _DECRYPT_CACHE[enc_str_b64]
    try:
        key  = _MASTER_KEY
        iv   = _b64.b64decode(iv_b64)
        data = _b64.b64decode(enc_str_b64)
        ks   = _hl.pbkdf2_hmac('sha256', key, iv, 1, dklen=len(data))
        result = bytes(a ^ b for a, b in zip(data, ks)).decode('utf-8')
        _DECRYPT_CACHE[enc_str_b64] = result
        return result
    except Exception:
        return ''
"""
