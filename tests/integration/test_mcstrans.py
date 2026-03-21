"""Integration test: analyze mcstransd source and check against reference policy."""
from pathlib import Path

import pytest

from sepgen.analyzer.c_analyzer import CAnalyzer
from sepgen.intent.classifier import IntentClassifier
from sepgen.generator.te_generator import TEGenerator
from sepgen.generator.fc_generator import FCGenerator
from sepgen.models.access import AccessType
from sepgen.models.intent import IntentType


MCSTRANS_SRC = Path(__file__).parent.parent.parent / "testing" / "mcstrans" / "src"


@pytest.mark.skipif(not MCSTRANS_SRC.exists(), reason="mcstrans test fixture not available")
class TestMcstransdAnalysis:

    def test_detects_syslog(self):
        analyzer = CAnalyzer()
        accesses = analyzer.analyze_directory(MCSTRANS_SRC)
        syslog = [a for a in accesses if a.access_type == AccessType.SYSLOG]
        assert len(syslog) > 0

    def test_detects_unix_socket(self):
        analyzer = CAnalyzer()
        accesses = analyzer.analyze_directory(MCSTRANS_SRC)
        classifier = IntentClassifier()
        intents = classifier.classify(accesses)
        unix_sock = [i for i in intents if i.intent_type == IntentType.UNIX_SOCKET_SERVER]
        assert len(unix_sock) > 0

    def test_detects_capabilities(self):
        analyzer = CAnalyzer()
        accesses = analyzer.analyze_directory(MCSTRANS_SRC)
        classifier = IntentClassifier()
        intents = classifier.classify(accesses)
        caps = [i for i in intents if i.intent_type == IntentType.SELF_CAPABILITY]
        assert len(caps) > 0

    def test_detects_daemon(self):
        analyzer = CAnalyzer()
        accesses = analyzer.analyze_directory(MCSTRANS_SRC)
        classifier = IntentClassifier()
        intents = classifier.classify(accesses)
        daemon = [i for i in intents if i.intent_type == IntentType.DAEMON_PROCESS]
        assert len(daemon) > 0

    def test_generates_correct_base_types(self):
        analyzer = CAnalyzer()
        accesses = analyzer.analyze_directory(MCSTRANS_SRC)
        classifier = IntentClassifier()
        intents = classifier.classify(accesses)
        generator = TEGenerator("setrans")
        policy = generator.generate(intents)

        type_names = [t.name for t in policy.types]
        assert "setrans_t" in type_names
        assert "setrans_exec_t" in type_names

    def test_generates_self_rules(self):
        analyzer = CAnalyzer()
        accesses = analyzer.analyze_directory(MCSTRANS_SRC)
        classifier = IntentClassifier()
        intents = classifier.classify(accesses)
        generator = TEGenerator("setrans")
        policy = generator.generate(intents)

        self_rules = [r for r in policy.allow_rules if r.target == "self"]
        object_classes = {r.object_class for r in self_rules}
        assert "capability" in object_classes
        assert "process" in object_classes
        assert "unix_stream_socket" in object_classes

    def test_generates_syslog_macro(self):
        analyzer = CAnalyzer()
        accesses = analyzer.analyze_directory(MCSTRANS_SRC)
        classifier = IntentClassifier()
        intents = classifier.classify(accesses)
        generator = TEGenerator("setrans")
        policy = generator.generate(intents)

        macro_names = [m.name for m in policy.macro_calls]
        assert "logging_send_syslog_msg" in macro_names
        assert "init_daemon_domain" in macro_names

    def test_resolves_define_paths(self):
        analyzer = CAnalyzer()
        accesses = analyzer.analyze_file(MCSTRANS_SRC / "mcstransd.c")
        paths = [a.path for a in accesses if a.path]
        assert any("setrans" in p for p in paths)
