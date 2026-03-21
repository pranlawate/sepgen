from sepgen.analyzer.c_analyzer import CAnalyzer
from sepgen.models.access import AccessType


def test_signal_include_emits_process_control():
    code = '''
    #include <signal.h>
    #include <stdio.h>
    int main() { return 0; }
    '''
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    signal_accesses = [
        a for a in accesses
        if a.access_type == AccessType.PROCESS_CONTROL
        and a.details.get("process_perm") == "signal_perms"
    ]
    assert len(signal_accesses) == 1


def test_no_signal_include_no_access():
    code = '''
    #include <stdio.h>
    int main() { return 0; }
    '''
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    signal_accesses = [
        a for a in accesses
        if a.details.get("process_perm") == "signal_perms"
    ]
    assert len(signal_accesses) == 0
