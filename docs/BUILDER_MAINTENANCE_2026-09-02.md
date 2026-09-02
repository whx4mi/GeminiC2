# Manutenção do Builder — 2026-09-02

## Objetivo

Esta manutenção corrige falhas de isolamento de ambiente, diagnóstico e captura
de saída do Builder. O pipeline, as opções interativas e o artefato esperado
permanecem os mesmos.

Nenhuma funcionalidade do Agent foi removida, desativada ou reescrita. O arquivo
`agente/agent.py` já possuía uma alteração local no texto do log de versão antes
desta manutenção; essa alteração foi preservada e não faz parte do trabalho no
Builder.

## Alterações realizadas

### `strategies/compilation.py`

1. **Resolução do PyInstaller pelo interpretador atual**
   - Antes: o processo chamava o executável textual `pyinstaller`, que podia ser
     resolvido de uma instalação global diferente da `.venv` do projeto.
   - Agora: usa `sys.executable -m PyInstaller`, da mesma forma estrutural que o
     pipeline Nuitka já usa `sys.executable -m nuitka`.
   - Efeito esperado: o compilador e suas dependências passam a ser resolvidos
     pelo mesmo ambiente Python que iniciou o Builder.

2. **Preflight dos compiladores**
   - Foi adicionada `_require_compiler_module()`.
   - PyInstaller e Nuitka são localizados com `importlib.util.find_spec()` antes
     da criação do subprocesso.
   - Em caso de ausência, a falha ocorre cedo e informa qual interpretador está
     em uso, sem tentar executar um comando global ou ambíguo.

3. **Validação do contexto de compilação**
   - Foi adicionada `_validate_compilation_context()`.
   - Valida a existência do diretório lógico de build, do script de entrada e do
     nome do artefato antes de iniciar o compilador.
   - Builds válidos seguem o mesmo fluxo; contextos incompletos recebem um erro
     mais direto.

4. **Detecção de OpenCV sem importação antecipada**
   - Antes: `cv2` era importado ao carregar o módulo, tornando ineficaz o aviso
     de ausência existente dentro do pipeline.
   - Agora: a localização é consultada com `find_spec('cv2')`, sem importar o
     pacote durante a inicialização do Builder.
   - A opção `--add-binary`, quando OpenCV está presente, foi preservada.

5. **Saída tolerante ao encoding do Windows**
   - Foi adicionada `_output_encoding()` para escolher o encoding do console ou
     do sistema.
   - PyInstaller agora usa `errors='replace'` e `check=False`, preservando o
     código de retorno e impedindo que bytes inválidos mascarem a falha real.
   - Nuitka reutiliza a mesma seleção de encoding e mantém a leitura incremental
     de saída que já existia.

### `Builder.py`

Foram removidos somente imports sem qualquer referência no arquivo:

- `base64`;
- `json`;
- `NullSignature`.

Essa limpeza não remove classes, funções, estratégias, opções de menu nem etapas
do pipeline. `CodeSigningStrategy`, `LoaderPackingStrategy`, estratégias de
compilação, saída em script e demais caminhos existentes permanecem referenciados.

### Testes

Foi criado `tests/test_builder_contracts.py`. Os testes simulam os subprocessos;
eles não executam PyInstaller, Nuitka, Builder, Agent, stagers ou payloads.

Cobertura adicionada:

- PyInstaller iniciado por `sys.executable -m PyInstaller`;
- diagnóstico quando PyInstaller não existe no interpretador atual;
- captura tolerante de saída;
- Nuitka iniciado por `sys.executable -m nuitka`;
- preservação do caminho esperado do artefato final.

Em `tests/test_architecture_contracts.py`, a limpeza do teste SQLite passou a
incluir o arquivo `-journal`, além de banco, `-wal` e `-shm`. Isso evita deixar
artefatos temporários no repositório.

## Contratos preservados

- `AgentBuilder`, `PyInstallerCompilation`, `NuitkaCompilation` e `ScriptOutput`
  mantêm seus nomes e assinaturas públicas.
- A ordem das etapas continua definida por `main_interactive()`.
- As opções `onefile`, saída sem console no Windows, diretórios de trabalho,
  nome de saída e argumentos adicionais foram preservadas.
- As listas existentes de imports ocultos, pacotes coletados e módulos do Nuitka
  não foram reduzidas ou ampliadas.
- O artefato final continua sendo esperado em `build_dir/dist/<output>` para os
  compiladores e no script preparado para `ScriptOutput`.
- A finalização continua movendo o artefato produzido para `payloads/`.

## Validação executada

Resultados após as alterações:

- `python -m unittest discover -s tests -v`: **7 testes aprovados**;
- `python -m pip check`: **nenhuma dependência quebrada detectada**;
- `node --check redirector/worker.js`: **sintaxe válida**;
- compilação sintática dos arquivos Python alterados: **aprovada**;
- `git diff --check`: **sem erro de whitespace**; permanecem apenas avisos de
  conversão LF/CRLF já associados ao ambiente Windows.

## Limitações da validação

Nenhum executável real foi produzido. Por isso, tamanho final, tempo de build e
empacotamento de dependências nativas não foram medidos. Rotinas sensíveis,
templates alternativos, Agent Tor, stagers e assinatura de executáveis não foram
executados nem modificados.

Qualquer limpeza futura em `agente/agent.py` deve ser tratada separadamente e só
pode ocorrer após comprovação de que o símbolo não participa de dispatchers,
imports dinâmicos, callbacks, threads ou estratégias de empacotamento. Nesta
manutenção, nenhuma limpeza foi aplicada ao Agent.
