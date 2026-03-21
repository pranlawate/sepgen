from sepgen.analyzer.c_analyzer import CAnalyzer
from sepgen.models.access import AccessType


def test_variable_path_in_fopen():
    code = '''
    char *config = "/etc/myapp.conf";
    fopen(config, "r");
    '''
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    paths = [a.path for a in accesses if a.access_type == AccessType.FILE_READ]
    assert "/etc/myapp.conf" in paths


def test_variable_path_in_unlink():
    code = '''
    const char *sock = "/var/run/myapp.sock";
    unlink(sock);
    '''
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    paths = [a.path for a in accesses if a.access_type == AccessType.FILE_UNLINK]
    assert "/var/run/myapp.sock" in paths


def test_variable_and_literal_paths():
    code = '''
    char *path = "/etc/app.conf";
    fopen(path, "r");
    fopen("/var/log/app.log", "w");
    '''
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    paths = [a.path for a in accesses]
    assert "/etc/app.conf" in paths
    assert "/var/log/app.log" in paths
