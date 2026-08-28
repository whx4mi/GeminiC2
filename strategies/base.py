# strategies/base.py

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

class BuildContext:
    """
    Um objeto para carregar o estado e os dados entre as etapas do build.
    Funciona como uma "mochila" que cada estratégia carrega e pode modificar.
    """
    def __init__(self, config: dict):
        # Configurações iniciais do build, vindas da interface do usuário
        self.config: dict = config
        
        # Caminho para o diretório temporário do build
        self.build_dir: Optional[Path] = None
        
        # Caminho para o script de entrada que será processado pela próxima etapa
        # Começa com o template original e é modificado pelas estratégias de ofuscação
        self.entry_script_path: Optional[Path] = None
        
        # Caminho para o artefato final gerado pela estratégia de compilação (.exe, .py)
        self.final_artifact_path: Optional[Path] = None

    def __str__(self):
        """Representação em string para facilitar o debug."""
        return (
            f"BuildContext(\n"
            f"  Config: {self.config.get('output')}\n"
            f"  Build Dir: {self.build_dir}\n"
            f"  Entry Script: {self.entry_script_path}\n"
            f"  Final Artifact: {self.final_artifact_path}\n"
            f")"
        )

class BuildStrategy(ABC):
    """Classe base para todas as estratégias."""
    @abstractmethod
    def execute(self, context: BuildContext) -> BuildContext:
        """
        Executa a lógica da estratégia.
        Recebe o contexto atual, executa sua tarefa e retorna o contexto modificado.
        """
        pass

# Agora definimos as interfaces para cada TIPO de estratégia
# Elas herdam de BuildStrategy para manter um padrão, mas poderiam ser independentes.

class ObfuscationStrategy(BuildStrategy):
    """Interface para todas as estratégias de ofuscação de código-fonte."""
    pass

class CompilationStrategy(BuildStrategy):
    """Interface para todas as estratégias de compilação ou saída."""
    pass

class SignatureStrategy(BuildStrategy):
    """Interface para todas as estratégias de assinatura de código."""
    pass

class MutationStrategy(BuildStrategy):
    """Interface para todas as estratégias de mutação e polimorfismo."""
    pass
