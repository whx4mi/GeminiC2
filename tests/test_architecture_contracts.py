import ast
import re
import sqlite3
import subprocess
import sys
import unittest
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _tree(relative_path: str) -> ast.AST:
    return ast.parse((ROOT / relative_path).read_text(encoding="utf-8"))


def _flask_routes(relative_path: str) -> set[str]:
    routes = set()
    for node in ast.walk(_tree(relative_path)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr == "route"
                and decorator.args
                and isinstance(decorator.args[0], ast.Constant)
            ):
                routes.add(decorator.args[0].value)
    return routes


def _route_regex(route: str) -> str:
    parts = []
    position = 0
    for match in re.finditer(r"<(?:(path):)?[^>]+>", route):
        parts.append(re.escape(route[position : match.start()]))
        parts.append(".+" if match.group(1) else "[^/]+")
        position = match.end()
    parts.append(re.escape(route[position:]))
    return "".join(parts)


class ArchitectureContractTests(unittest.TestCase):
    def test_panel_fetch_routes_exist_on_canonical_server(self):
        html = (ROOT / "templates" / "panel.html").read_text(encoding="utf-8")
        references = set()
        for match in re.finditer(r'''fetch\(\s*([`'"])(.*?)\1''', html, re.DOTALL):
            value = match.group(2).replace("${window.location.origin}", "")
            if value.startswith("/"):
                references.add(value.split("?", 1)[0])

        routes = _flask_routes("ServidorHomologacao.py")
        missing = []
        for reference in sorted(references):
            sample = re.sub(r"\$\{[^}]+\}", "VALUE", reference)
            if not any(re.fullmatch(_route_regex(route), sample) for route in routes):
                missing.append(reference)

        self.assertEqual([], missing)

    def test_server_and_agent_command_sets_match(self):
        server = _tree("ServidorHomologacao.py")
        agent = _tree("agente/agent.py")

        allowed = set()
        for node in ast.walk(server):
            if isinstance(node, ast.FunctionDef) and node.name == "issue_command_route":
                for child in ast.walk(node):
                    if not isinstance(child, ast.Assign):
                        continue
                    if any(isinstance(target, ast.Name) and target.id == "ALLOWED_COMMANDS" for target in child.targets):
                        allowed = {
                            item.value
                            for item in child.value.elts
                            if isinstance(item, ast.Constant)
                        }

        dispatch_names = {"THREADED_TASKS", "SYNC_TASKS", "NO_RETURN_TASKS"}
        implemented = {"sleep"}
        for node in agent.body:
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in dispatch_names and isinstance(node.value, ast.Dict):
                    implemented.update(
                        key.value for key in node.value.keys if isinstance(key, ast.Constant)
                    )
                elif (
                    isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Name)
                    and target.value.id in dispatch_names
                    and isinstance(target.slice, ast.Constant)
                ):
                    implemented.add(target.slice.value)

        self.assertEqual(allowed, implemented)

    def test_database_initialization_is_idempotent(self):
        sys.path.insert(0, str(ROOT))
        import database

        original_db_file = database.DB_FILE
        test_db = ROOT / ".architecture_contract.sqlite"
        artifacts = [test_db, Path(f"{test_db}-wal"), Path(f"{test_db}-shm")]
        try:
            for artifact in artifacts:
                artifact.unlink(missing_ok=True)
            database.DB_FILE = str(test_db)
            database.init_db()
            database.init_db()
            connection = sqlite3.connect(database.DB_FILE)
            task_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(tasks)")
            }
            agent_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(agents)")
            }
            connection.close()

            self.assertTrue(
                {"timestamp_started", "updated_at", "issued_by"} <= task_columns
            )
            self.assertTrue({"tags", "notes"} <= agent_columns)
        finally:
            database.DB_FILE = original_db_file
            for artifact in artifacts:
                artifact.unlink(missing_ok=True)

    def test_panel_inline_javascript_is_valid(self):
        if not shutil.which("node"):
            self.skipTest("Node.js não está disponível para validar o JavaScript")
        html = (ROOT / "templates" / "panel.html").read_text(encoding="utf-8")
        javascript = "\n".join(
            re.findall(r"<script(?:\s[^>]*)?>(.*?)</script>", html, re.DOTALL | re.IGNORECASE)
        ).replace("{{ user_role }}", "Administrator")
        result = subprocess.run(
            ["node", "--check", "-"],
            input=javascript,
            text=True,
            capture_output=True,
            encoding="utf-8",
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
