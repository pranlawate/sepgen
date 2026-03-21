from sepgen.analyzer.c_analyzer import CAnalyzer
from sepgen.intent.classifier import IntentClassifier
from sepgen.models.access import AccessType
from sepgen.models.intent import IntentType


def test_unix_socket_vs_tcp():
    unix_code = 'socket(PF_UNIX, SOCK_STREAM, 0); bind(sock, addr, len);'
    tcp_code = 'socket(AF_INET, SOCK_STREAM, 0); bind(sock, addr, len);'

    analyzer = CAnalyzer()
    unix_accesses = analyzer.analyze_string(unix_code)
    tcp_accesses = analyzer.analyze_string(tcp_code)

    classifier = IntentClassifier()
    unix_intents = classifier.classify(unix_accesses)
    tcp_intents = classifier.classify(tcp_accesses)

    unix_bind = [i for i in unix_intents if i.intent_type != IntentType.UNKNOWN]
    assert any(i.intent_type == IntentType.UNIX_SOCKET_SERVER for i in unix_bind)

    tcp_bind = [i for i in tcp_intents if i.intent_type != IntentType.UNKNOWN]
    assert any(i.intent_type == IntentType.NETWORK_SERVER for i in tcp_bind)


def test_socket_domain_propagated_to_bind():
    code = 'socket(AF_UNIX, SOCK_STREAM, 0); bind(fd, &addr, sizeof(addr));'
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    bind_accesses = [a for a in accesses if a.access_type == AccessType.SOCKET_BIND]
    assert len(bind_accesses) == 1
    assert bind_accesses[0].details.get("domain") == "AF_UNIX"


def test_inet6_classified_as_network_server():
    code = 'socket(AF_INET6, SOCK_STREAM, 0); bind(fd, addr, len);'
    analyzer = CAnalyzer()
    accesses = analyzer.analyze_string(code)

    classifier = IntentClassifier()
    intents = classifier.classify(accesses)
    bind_intents = [i for i in intents if i.intent_type == IntentType.NETWORK_SERVER]
    assert len(bind_intents) == 1
