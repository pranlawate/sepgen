from sepgen.analyzer.c_analyzer import CAnalyzer
from sepgen.models.access import AccessType


def test_resolve_define_in_fopen():
    code = '''
    #define CONFIG_FILE "/etc/myapp.conf"

    void init() {
        FILE *f = fopen(CONFIG_FILE, "r");
    }
    '''
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    paths = [a.path for a in accesses]
    assert "/etc/myapp.conf" in paths


def test_resolve_define_in_fopen_write():
    code = '''
    #define SOCKET_PATH "/var/run/setrans/.setrans-unix"

    void init() {
        FILE *f = fopen(SOCKET_PATH, "w");
    }
    '''
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    paths = [a.path for a in accesses]
    assert "/var/run/setrans/.setrans-unix" in paths


def test_define_does_not_affect_non_string_macros():
    code = '''
    #define MAX_CONN 128
    #define CONFIG "/etc/app.conf"

    fopen(CONFIG, "r");
    '''
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    paths = [a.path for a in accesses]
    assert "/etc/app.conf" in paths


def test_multiple_defines():
    code = '''
    #define LOG_PATH "/var/log/myapp.log"
    #define PID_PATH "/var/run/myapp.pid"

    fopen(LOG_PATH, "r");
    fopen(PID_PATH, "w");
    '''
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    paths = [a.path for a in accesses]
    assert "/var/log/myapp.log" in paths
    assert "/var/run/myapp.pid" in paths
