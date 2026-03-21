from sepgen.analyzer.c_analyzer import CAnalyzer
from sepgen.intent.classifier import IntentClassifier
from sepgen.models.access import AccessType
from sepgen.models.intent import IntentType


def test_detect_setrlimit():
    code = 'setrlimit(RLIMIT_NOFILE, &rl);'
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    proc_accesses = [a for a in accesses if a.access_type == AccessType.PROCESS_CONTROL]
    assert len(proc_accesses) == 1
    assert proc_accesses[0].details.get("capability") == "sys_resource"


def test_detect_cap_set_proc():
    code = 'cap_set_proc(caps);'
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    cap_accesses = [a for a in accesses if a.access_type == AccessType.CAPABILITY]
    assert len(cap_accesses) == 1


def test_detect_cap_init():
    code = 'cap_t caps = cap_init();'
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    cap_accesses = [a for a in accesses if a.access_type == AccessType.CAPABILITY]
    assert len(cap_accesses) == 1


def test_capability_classifies_as_self_capability():
    classifier = IntentClassifier()

    from sepgen.models.access import Access
    accesses = [
        Access(AccessType.PROCESS_CONTROL, "", "setrlimit", {"capability": "sys_resource"}),
        Access(AccessType.CAPABILITY, "", "cap_set_proc", {}),
    ]
    intents = classifier.classify(accesses)

    cap_intents = [i for i in intents if i.intent_type == IntentType.SELF_CAPABILITY]
    assert len(cap_intents) == 2
