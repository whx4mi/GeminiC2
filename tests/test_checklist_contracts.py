import ast
import json
import re
import shutil
import subprocess
import unittest
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKLIST = ROOT / "docs" / "manual-validation-checklist.html"


class _IdCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()

    def handle_starttag(self, _tag, attrs):
        for name, value in attrs:
            if name == "id" and value:
                self.ids.add(value)


def _agent_commands() -> set[str]:
    tree = ast.parse((ROOT / "agente" / "agent.py").read_text(encoding="utf-8"))
    dispatchers = {"THREADED_TASKS", "SYNC_TASKS", "NO_RETURN_TASKS"}
    commands = {"sleep"}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Name)
                and target.id in dispatchers
                and isinstance(node.value, ast.Dict)
            ):
                commands.update(
                    key.value for key in node.value.keys if isinstance(key, ast.Constant)
                )
            elif (
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Name)
                and target.value.id in dispatchers
                and isinstance(target.slice, ast.Constant)
            ):
                commands.add(target.slice.value)
    return commands


def _javascript_array(html: str, variable: str) -> list[str]:
    match = re.search(
        rf"const\s+{re.escape(variable)}\s*=\s*(\[.*?\]);",
        html,
        re.DOTALL,
    )
    if not match:
        raise AssertionError(f"Array JavaScript não encontrado: {variable}")
    return json.loads(match.group(1))


class ChecklistContractTests(unittest.TestCase):
    def test_html_command_matrix_matches_agent_dispatchers(self):
        html = CHECKLIST.read_text(encoding="utf-8")
        listed = {
            "sleep",
            "cleanup",
            *_javascript_array(html, "threaded"),
            *_javascript_array(html, "synchronous"),
        }
        self.assertEqual(_agent_commands(), listed)

    def test_html_has_report_controls_and_no_network_calls(self):
        html = CHECKLIST.read_text(encoding="utf-8")
        parser = _IdCollector()
        parser.feed(html)
        self.assertTrue(
            {
                "export-html",
                "export-json",
                "import-json",
                "print-report",
                "reset-all",
                "add-issue",
            }
            <= parser.ids
        )
        self.assertNotRegex(html, r"\b(?:fetch|XMLHttpRequest)\s*\(")

    def test_inline_javascript_is_valid(self):
        if not shutil.which("node"):
            self.skipTest("Node.js não está disponível para validar o JavaScript")
        html = CHECKLIST.read_text(encoding="utf-8")
        scripts = "\n".join(
            re.findall(r"<script(?:\s[^>]*)?>(.*?)</script>", html, re.DOTALL | re.IGNORECASE)
        )
        result = subprocess.run(
            ["node", "--check", "-"],
            input=scripts,
            text=True,
            capture_output=True,
            encoding="utf-8",
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
