from pathlib import Path
from sepgen.analyzer.c_analyzer import CAnalyzer
from sepgen.models.access import AccessType


def test_analyze_directory(tmp_path):
    (tmp_path / "main.c").write_text('fopen("/etc/app.conf", "r");')
    (tmp_path / "net.c").write_text('socket(AF_INET, SOCK_STREAM, 0);')
    (tmp_path / "README.md").write_text("Not a C file")

    analyzer = CAnalyzer()
    accesses = analyzer.analyze_directory(tmp_path)

    assert len(accesses) == 2
    types = {a.access_type for a in accesses}
    assert AccessType.FILE_READ in types
    assert AccessType.SOCKET_CREATE in types


def test_analyze_directory_recursive(tmp_path):
    subdir = tmp_path / "sub"
    subdir.mkdir()
    (tmp_path / "main.c").write_text('syslog(LOG_INFO, "hi");')
    (subdir / "helper.c").write_text('fopen("/etc/helper.conf", "r");')

    analyzer = CAnalyzer()
    accesses = analyzer.analyze_directory(tmp_path)

    assert len(accesses) >= 2
    paths = [a.path for a in accesses if a.path]
    assert "/etc/helper.conf" in paths


def test_analyze_directory_preserves_source_file(tmp_path):
    (tmp_path / "app.c").write_text('fopen("/etc/app.conf", "r");')

    analyzer = CAnalyzer()
    accesses = analyzer.analyze_directory(tmp_path)

    assert len(accesses) == 1
    assert accesses[0].source_file is not None
    assert "app.c" in accesses[0].source_file
