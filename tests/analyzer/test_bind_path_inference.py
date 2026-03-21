from sepgen.analyzer.c_analyzer import CAnalyzer
from sepgen.models.access import AccessType


def test_bind_path_inferred_from_unlink():
    """unlink('/var/run/x') before bind() → bind gets the path."""
    code = '''
    unlink("/var/run/setrans/.setrans-unix");
    sock = socket(PF_UNIX, SOCK_STREAM, 0);
    bind(sock, &addr, len);
    '''
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    bind_access = [a for a in accesses if a.access_type == AccessType.SOCKET_BIND]
    assert len(bind_access) == 1
    assert bind_access[0].path == "/var/run/setrans/.setrans-unix"


def test_bind_path_not_inferred_for_inet():
    """AF_INET bind should not get unlink path."""
    code = '''
    unlink("/var/run/setrans/.setrans-unix");
    sock = socket(AF_INET, SOCK_STREAM, 0);
    bind(sock, &addr, len);
    '''
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    bind_access = [a for a in accesses if a.access_type == AccessType.SOCKET_BIND]
    assert len(bind_access) == 1
    assert bind_access[0].path == ""


def test_bind_path_not_inferred_from_non_var_run():
    """unlink on /tmp/ should not be used for bind path."""
    code = '''
    unlink("/tmp/something");
    sock = socket(PF_UNIX, SOCK_STREAM, 0);
    bind(sock, &addr, len);
    '''
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    bind_access = [a for a in accesses if a.access_type == AccessType.SOCKET_BIND]
    assert len(bind_access) == 1
    assert bind_access[0].path == ""
