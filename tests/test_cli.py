# SPDX-License-Identifier: MIT
import json
import subprocess
import sys

from voltage_verify import __version__
from voltage_verify.cli import main


def test_module_entry_point_prints_version():
    out = subprocess.run([sys.executable, "-m", "voltage_verify", "--version"], capture_output=True, text=True, check=False)
    assert out.returncode == 0
    assert __version__ in out.stdout


def test_manifest_command_writes_a_valid_manifest(tmp_path, capsys):
    art = tmp_path / "prompt.txt"
    art.write_text("hello")
    out = tmp_path / "manifest.json"
    code = main(
        [
            "manifest",
            "--image",
            "ghcr.io/org/app:1",
            "--image-digest",
            "sha256:" + "cd" * 32,
            "--artifact",
            str(art),
            "--extra",
            "run=test",
            "-o",
            str(out),
        ]
    )
    assert code == 0
    manifest = json.loads(out.read_text())
    assert manifest["workload"]["image"]["digest"] == "sha256:" + "cd" * 32
    assert manifest["workload"]["artifacts"][0]["name"] == "prompt.txt"
    printed = capsys.readouterr().out
    assert "commitment256" in printed and manifest["challenge"] in printed


def test_verify_rejects_unusable_bundle(tmp_path, capsys):
    bad = tmp_path / "bundle.json"
    bad.write_text("{}")
    assert main(["verify", str(bad)]) == 2
    assert "unsupported bundle format" in capsys.readouterr().err
