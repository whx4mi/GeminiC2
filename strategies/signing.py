# strategies/signature.py

import sys
import subprocess
import shutil
from pathlib import Path
from .base import BuildStrategy, BuildContext, SignatureStrategy
from rich.console import Console # Importa diretamente do rich
console = Console() # Cria uma instância local


class CodeSigningStrategy(SignatureStrategy): # <-- CORREÇÃO: Herda de BaseStrategy
    """
    Forja uma assinatura de código em um executável usando um script externo (ex: CarbonCopy/sigthief).
    Clona um certificado de um host legítimo para assinar o artefato.
    """
    
    def execute(self, context: BuildContext) -> BuildContext:
        # --- Verificações Iniciais ---
        if not context.config.get('sign_executable', False):
            # Esta etapa foi desabilitada pelo usuário.
            return context
        
        # Verifica se o artefato da compilação anterior realmente existe
        if not context.final_artifact_path or not context.final_artifact_path.exists():
            console.print("[warning]Artefato final não encontrado. Pulando etapa de assinatura.[/warning]")
            return context

        console.print("[info]Iniciando forjamento de assinatura de código...[/info]")
        
        # --- Localização do Script de Assinatura ---
        # Usa sys.executable para garantir que o mesmo ambiente Python seja usado.
        python_executable = sys.executable
        # Assume que o script de assinatura está na raiz do projeto.
        base_dir = Path(__file__).parent.parent
        # Renomeado para ser mais genérico, sigthief.py é o nome comum da ferramenta.
        signing_script = base_dir / "sigthief.py" 
        
        if not signing_script.exists():
            console.print(f"[error]Script de assinatura '{signing_script.name}' não encontrado em '{base_dir}'.")
            console.print("[warning]Pulando etapa de assinatura. Baixe o script e coloque-o na raiz do projeto.[/warning]")
            return context
        
        # --- Preparação dos Parâmetros ---
        source_host = context.config.get('sign_host', 'www.microsoft.com')
        original_path = context.final_artifact_path
        # Cria um nome de arquivo temporário para o executável assinado
        signed_path = original_path.with_suffix(f"{original_path.suffix}.signed")
        
        # --- Construção e Execução do Comando ---
        command = [
            python_executable,
            str(signing_script),
            '-t', str(original_path), # Arquivo alvo
            '-r', str(source_host),   # Host remoto para clonar certificado
            '-o', str(signed_path)    # Arquivo de saída
        ]
        
        console.print(f"[info]Clonando certificado de '{source_host}' e aplicando em '{original_path.name}'...[/info]")
        console.print(f"[info]Comando: {' '.join(command)}[/info]")
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=90 # Aumentado para 90s para redes lentas
            )
            
            if result.returncode != 0:
                # Se falhar, imprime a saída para ajudar na depuração
                error_output = result.stdout + "\n" + result.stderr
                raise RuntimeError(f"O script de assinatura falhou:\n{error_output}")
            
            # --- Substituição e Limpeza ---
            # Substitui o executável original pelo novo, agora assinado
            original_path.unlink()
            shutil.move(str(signed_path), str(original_path))
            
            console.print(f"[success]Assinatura de '{source_host}' aplicada com sucesso![/success]")
            
            return context
            
        except subprocess.TimeoutExpired:
            console.print("[error]Timeout ao executar o script de assinatura (>90s). Verifique sua conexão.[/error]")
            # Retorna o contexto sem a assinatura para não quebrar o build
            return context
        except Exception as e:
            console.print(f"[warning]Erro ao assinar o executável: {e}[/warning]")
            console.print("[warning]Continuando o build sem a assinatura.[/warning]")
            # Garante que o arquivo temporário .signed seja removido se existir
            if signed_path.exists():
                signed_path.unlink()
            return context

# Adicione aqui outras estratégias de assinatura se necessário, como NullSignature
class NullSignature(BuildStrategy):
    """Uma estratégia que não faz nada, usada como placeholder."""
    def execute(self, context: BuildContext) -> BuildContext:
        # console.print("[info]Estratégia de assinatura nula. Nenhuma ação realizada.[/info]")
        return context
