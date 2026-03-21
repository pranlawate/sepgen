from sepgen.analyzer.c_analyzer import CAnalyzer
from sepgen.models.access import AccessType
from sepgen.intent.classifier import IntentClassifier
from sepgen.models.access import Access
from sepgen.models.intent import IntentType


def test_detect_openlog():
    code = '''
    #include <syslog.h>
    int main() {
        openlog("myapp", LOG_PID, LOG_DAEMON);
        syslog(LOG_INFO, "Started");
    }
    '''
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    syslog_accesses = [a for a in accesses if a.access_type == AccessType.SYSLOG]
    assert len(syslog_accesses) == 2
    funcs = {a.details["function"] for a in syslog_accesses}
    assert funcs == {"openlog", "syslog"}
    assert syslog_accesses[0].syscall == "connect"
    assert "/dev/log" in syslog_accesses[0].path


def test_syslog_deduplication():
    code = '''
    syslog(LOG_INFO, "msg1");
    syslog(LOG_ERR, "msg2");
    syslog(LOG_WARNING, "msg3");
    openlog("app", 0, 0);
    '''
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    syslog_accesses = [a for a in accesses if a.access_type == AccessType.SYSLOG]
    assert len(syslog_accesses) == 2
    funcs = {a.details["function"] for a in syslog_accesses}
    assert funcs == {"syslog", "openlog"}


def test_syslog_maps_to_logging_macro():
    classifier = IntentClassifier()
    intents = classifier.classify([Access(AccessType.SYSLOG, "/dev/log", "connect", {})])
    assert len(intents) == 1
    assert intents[0].intent_type == IntentType.SYSLOG
