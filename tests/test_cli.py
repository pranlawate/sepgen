import pytest
from sepgen.cli import create_parser, main


def test_cli_has_analyze_command():
    parser = create_parser()
    args = parser.parse_args(['analyze', '/path/to/source'])
    assert args.command == 'analyze'
    assert args.source_path == '/path/to/source'


def test_cli_has_trace_command():
    parser = create_parser()
    args = parser.parse_args(['trace', '/usr/bin/app'])
    assert args.command == 'trace'
    assert args.binary == '/usr/bin/app'


def test_cli_verbosity_flags():
    parser = create_parser()
    args = parser.parse_args(['trace', '/usr/bin/app', '-v'])
    assert args.verbose >= 1
    args = parser.parse_args(['trace', '/usr/bin/app', '-vv'])
    assert args.verbose >= 2


def test_cli_auto_merge_flag():
    parser = create_parser()
    args = parser.parse_args(['trace', '/usr/bin/app', '-y'])
    assert args.auto_merge is True


def test_analyze_workflow(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    c_file = tmp_path / "test.c"
    c_file.write_text('''
    #include <stdio.h>
    int main() {
        fopen("/etc/test.conf", "r");
        return 0;
    }
    ''')

    result = main(['analyze', str(c_file), '--name', 'testapp'])

    assert result == 0
    assert (tmp_path / "testapp.te").exists()
    assert (tmp_path / "testapp.fc").exists()

    te_content = (tmp_path / "testapp.te").read_text()
    assert "policy_module(testapp," in te_content
    assert "type testapp_t;" in te_content
