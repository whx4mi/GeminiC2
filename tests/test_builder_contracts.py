import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from strategies.base import BuildContext
from strategies.compilation import NuitkaCompilation, PyInstallerCompilation


class _FakeStdout:
    def __init__(self):
        self._lines = [b"compilando\xff\n", b""]

    def readline(self):
        return self._lines.pop(0)


class _FakeProcess:
    def __init__(self):
        self.stdout = _FakeStdout()

    def poll(self):
        return 0


class BuilderContractTests(unittest.TestCase):
    def setUp(self):
        workspace = Path(__file__).resolve().parents[1]
        self.context = BuildContext(
            {
                "output": "agent.exe",
                "platform": "windows",
                "extra_args": [],
            }
        )
        self.context.build_dir = workspace
        self.context.entry_script_path = workspace / "Builder.py"

    @patch("strategies.compilation.subprocess.run")
    @patch("strategies.compilation.importlib.util.find_spec")
    def test_pyinstaller_uses_current_interpreter_and_tolerant_output(
        self, find_spec, run
    ):
        find_spec.side_effect = lambda name: (
            SimpleNamespace(origin=str(Path("cv2") / "__init__.py"))
            if name == "cv2"
            else SimpleNamespace(origin=None)
        )
        run.return_value = subprocess.CompletedProcess([], 0, "ok", "")

        result = PyInstallerCompilation().execute(self.context)

        command = run.call_args.args[0]
        self.assertEqual([sys.executable, "-m", "PyInstaller"], command[:3])
        self.assertEqual("replace", run.call_args.kwargs["errors"])
        self.assertFalse(run.call_args.kwargs["check"])
        self.assertEqual(
            self.context.build_dir / "dist" / "agent.exe",
            result.final_artifact_path,
        )

    @patch("strategies.compilation.subprocess.run")
    @patch("strategies.compilation.importlib.util.find_spec", return_value=None)
    def test_pyinstaller_reports_missing_module_before_execution(self, _find_spec, run):
        with self.assertRaisesRegex(RuntimeError, "interpretador atual"):
            PyInstallerCompilation().execute(self.context)
        run.assert_not_called()

    @patch("strategies.compilation.subprocess.Popen", return_value=_FakeProcess())
    @patch(
        "strategies.compilation.importlib.util.find_spec",
        return_value=SimpleNamespace(origin=None),
    )
    def test_nuitka_uses_current_interpreter(self, _find_spec, popen):
        result = NuitkaCompilation().execute(self.context)

        command = popen.call_args.args[0]
        self.assertEqual([sys.executable, "-m", "nuitka"], command[:3])
        self.assertEqual(
            self.context.build_dir / "dist" / "agent.exe",
            result.final_artifact_path,
        )


if __name__ == "__main__":
    unittest.main()
