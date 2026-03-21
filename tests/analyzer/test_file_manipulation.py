from sepgen.analyzer.c_analyzer import CAnalyzer
from sepgen.models.access import AccessType


def test_detect_unlink():
    code = 'unlink("/tmp/socket");'
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    unlink_accesses = [a for a in accesses if a.access_type == AccessType.FILE_UNLINK]
    assert len(unlink_accesses) == 1
    assert unlink_accesses[0].path == "/tmp/socket"
    assert unlink_accesses[0].syscall == "unlink"


def test_detect_chmod():
    code = 'chmod("/etc/myapp.conf", 0644);'
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    chmod_accesses = [a for a in accesses if a.access_type == AccessType.FILE_SETATTR]
    assert len(chmod_accesses) == 1
    assert chmod_accesses[0].path == "/etc/myapp.conf"
    assert chmod_accesses[0].syscall == "chmod"


def test_detect_open_readonly():
    code = 'int fd = open("/etc/myapp.conf", O_RDONLY);'
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    reads = [a for a in accesses if a.access_type == AccessType.FILE_READ]
    assert len(reads) == 1
    assert reads[0].path == "/etc/myapp.conf"


def test_detect_open_write():
    code = 'int fd = open("/var/log/myapp.log", O_WRONLY | O_CREAT, 0644);'
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    writes = [a for a in accesses if a.access_type == AccessType.FILE_WRITE]
    assert len(writes) == 1
    assert writes[0].path == "/var/log/myapp.log"


def test_detect_open_create():
    code = 'int fd = open("/tmp/newfile", O_CREAT, 0600);'
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    creates = [a for a in accesses if a.access_type == AccessType.FILE_CREATE]
    assert len(creates) == 1
    assert creates[0].path == "/tmp/newfile"


def test_unlink_with_define():
    code = '''
    #define SOCKET_PATH "/var/run/setrans/.setrans-unix"
    unlink(SOCKET_PATH);
    '''
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    unlink_accesses = [a for a in accesses if a.access_type == AccessType.FILE_UNLINK]
    assert len(unlink_accesses) == 1
    assert unlink_accesses[0].path == "/var/run/setrans/.setrans-unix"
