import pytest
from pathlib import Path
from unittest.mock import patch
from sepgen.cli import main


def test_trace_workflow_no_existing_policy(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    strace_output = tmp_path / "test.strace"
    strace_output.write_text('open("/etc/test.conf", O_RDONLY) = 3\n')

    with patch('sepgen.tracer.process_tracer.subprocess.run'):
        with patch('sepgen.tracer.process_tracer.ProcessTracer.trace', return_value=strace_output):
            result = main(['trace', '/usr/bin/test', '--name', 'testapp'])

            assert result == 0
            assert (tmp_path / "testapp.te").exists()
            assert (tmp_path / "testapp.fc").exists()


def test_trace_workflow_with_existing_policy(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    (tmp_path / "testapp.te").write_text('''policy_module(testapp, 1.0.0)
type testapp_t;
type testapp_exec_t;
''')
    (tmp_path / "testapp.fc").write_text('/usr/bin/test')

    strace_output = tmp_path / "test.strace"
    strace_output.write_text('open("/etc/test.conf", O_RDONLY) = 3\n')

    with patch('sepgen.tracer.process_tracer.subprocess.run'):
        with patch('sepgen.tracer.process_tracer.ProcessTracer.trace', return_value=strace_output):
            with patch('builtins.input', return_value='Y'):
                result = main(['trace', '/usr/bin/test', '--name', 'testapp'])
                assert result == 0
