import pytest
from sepgen.tracer.process_tracer import ProcessTracer


def test_build_strace_command_with_binary():
    """Test building strace command for binary"""
    tracer = ProcessTracer()
    cmd = tracer.build_strace_command(binary='/usr/bin/myapp', args='--config /etc/app.conf')

    assert 'strace' in cmd
    assert '-f' in cmd
    assert '/usr/bin/myapp' in cmd
    assert '--config' in cmd


def test_build_strace_command_with_pid():
    """Test building strace command for PID attachment"""
    tracer = ProcessTracer()
    cmd = tracer.build_strace_command(pid=1234)

    assert 'strace' in cmd
    assert '-p' in cmd
    assert '1234' in cmd


def test_build_command_requires_binary_or_pid():
    """Test that either binary or pid is required"""
    tracer = ProcessTracer()
    with pytest.raises(ValueError):
        tracer.build_strace_command()
