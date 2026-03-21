from sepgen.analyzer.include_analyzer import IncludeAnalyzer


def test_infer_syslog_capability():
    code = '#include <syslog.h>\n#include <stdio.h>'
    analyzer = IncludeAnalyzer()
    caps = analyzer.infer_capabilities(code)
    assert "syslog" in caps


def test_infer_capability_header():
    code = '#include <sys/capability.h>'
    analyzer = IncludeAnalyzer()
    caps = analyzer.infer_capabilities(code)
    assert "capability" in caps
    assert "process_setcap" in caps


def test_infer_multiple_headers():
    code = '''
    #include <syslog.h>
    #include <sys/resource.h>
    #include <signal.h>
    '''
    analyzer = IncludeAnalyzer()
    caps = analyzer.infer_capabilities(code)
    assert "syslog" in caps
    assert "setrlimit" in caps
    assert "signal_perms" in caps


def test_no_capabilities():
    code = '#include <stdio.h>\n#include <stdlib.h>'
    analyzer = IncludeAnalyzer()
    caps = analyzer.infer_capabilities(code)
    assert caps == []
