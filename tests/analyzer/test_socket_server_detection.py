from sepgen.analyzer.c_analyzer import CAnalyzer
from sepgen.models.access import AccessType


def test_detect_socket_server_pattern():
    code = '''
    int sock = socket(PF_UNIX, SOCK_STREAM, 0);
    bind(sock, ...);
    listen(sock, 5);
    int client = accept(sock, NULL, NULL);
    '''
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    listen_calls = [a for a in accesses if a.access_type == AccessType.SOCKET_LISTEN]
    accept_calls = [a for a in accesses if a.access_type == AccessType.SOCKET_ACCEPT]
    assert len(listen_calls) == 1
    assert listen_calls[0].syscall == "listen"
    assert len(accept_calls) == 1
    assert accept_calls[0].syscall == "accept"


def test_detect_listen_only():
    code = 'listen(fd, SOMAXCONN);'
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    listen_calls = [a for a in accesses if a.access_type == AccessType.SOCKET_LISTEN]
    assert len(listen_calls) == 1


def test_detect_accept_only():
    code = 'int conn = accept(sockfd, (struct sockaddr*)&addr, &len);'
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    accept_calls = [a for a in accesses if a.access_type == AccessType.SOCKET_ACCEPT]
    assert len(accept_calls) == 1
