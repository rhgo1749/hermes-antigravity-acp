"""Guards for the portable Antigravity ACP mux launcher."""

from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts" / "antigravity-acp-mux"


def test_wrapper_has_no_machine_specific_home_paths() -> None:
    source = WRAPPER.read_text(encoding="utf-8")
    assert "/home/" not in source
    assert "command -v antigravity-acp-official" in source
    assert '"$self_dir/antigravity-acp-mux.py"' in source


def test_wrapper_shell_syntax() -> None:
    completed = subprocess.run(
        ["sh", "-n", str(WRAPPER)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
