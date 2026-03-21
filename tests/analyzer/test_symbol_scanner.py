from sepgen.analyzer.symbol_scanner import SymbolScanner
from sepgen.models.access import AccessType


def test_detect_setuid():
    scanner = SymbolScanner()
    accesses = scanner.scan_string("setuid(0);")
    assert len(accesses) == 1
    assert accesses[0].access_type == AccessType.CAPABILITY
    assert accesses[0].details["capability"] == "setuid"


def test_detect_chroot():
    scanner = SymbolScanner()
    accesses = scanner.scan_string('chroot("/var/empty");')
    assert len(accesses) == 1
    assert accesses[0].details["capability"] == "sys_chroot"


def test_detect_shared_memory():
    scanner = SymbolScanner()
    accesses = scanner.scan_string('shm_open("/test", O_CREAT|O_RDWR, 0600);')
    assert len(accesses) == 1
    assert accesses[0].access_type == AccessType.IPC_POSIX
    assert accesses[0].details["ipc_type"] == "shm"


def test_deduplicate_across_files(tmp_path):
    (tmp_path / "a.c").write_text("setuid(0);")
    (tmp_path / "b.c").write_text("setuid(getuid());")
    scanner = SymbolScanner()
    accesses = scanner.scan_directory(tmp_path)
    setuid_accesses = [a for a in accesses if a.syscall == "setuid"]
    assert len(setuid_accesses) == 1


def test_no_false_positive_on_substring():
    scanner = SymbolScanner()
    accesses = scanner.scan_string("my_chroot_helper();")
    assert len(accesses) == 0


def test_multiple_capabilities():
    code = """
    setuid(0);
    setgid(0);
    chroot("/jail");
    """
    scanner = SymbolScanner()
    accesses = scanner.scan_string(code)
    caps = {a.details.get("capability") for a in accesses}
    assert caps == {"setuid", "setgid", "sys_chroot"}
