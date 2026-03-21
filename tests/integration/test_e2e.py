import pytest
from pathlib import Path
from unittest.mock import patch
from sepgen.cli import main


def test_e2e_analyze_then_trace(tmp_path, monkeypatch):
    """Test full workflow: analyze -> trace -> merge"""
    monkeypatch.chdir(tmp_path)

    c_file = tmp_path / "myapp.c"
    c_file.write_text('''
    #include <stdio.h>
    int main() {
        FILE *f = fopen("/etc/myapp.conf", "r");
        fclose(f);
        return 0;
    }
    ''')

    result = main(['analyze', str(c_file), '--name', 'myapp'])
    assert result == 0
    assert (tmp_path / "myapp.te").exists()

    te_content = (tmp_path / "myapp.te").read_text()
    assert "myapp_conf_t" in te_content

    strace_output = tmp_path / "test.strace"
    strace_output.write_text(
        'open("/etc/myapp.conf", O_RDONLY) = 3\n'
        'open("/var/run/myapp.pid", O_WRONLY|O_CREAT, 0644) = 4\n'
    )

    with patch('sepgen.tracer.process_tracer.subprocess.run'):
        with patch('sepgen.tracer.process_tracer.ProcessTracer.trace', return_value=strace_output):
            with patch('builtins.input', return_value='Y'):
                result = main(['trace', '/usr/bin/myapp', '--name', 'myapp'])
                assert result == 0

    te_content = (tmp_path / "myapp.te").read_text()
    assert "myapp_conf_t" in te_content
    assert "myapp_var_run_t" in te_content

    assert (tmp_path / "myapp.te.backup").exists()
