import subprocess, sys

def test_help_lists_commands():
    out = subprocess.run([sys.executable, "-m", "dva", "--help"], capture_output=True, text=True)
    assert out.returncode == 0
    assert "doctor" in out.stdout

def test_unknown_command_fails_cleanly():
    out = subprocess.run([sys.executable, "-m", "dva", "nope"], capture_output=True, text=True)
    assert out.returncode != 0
