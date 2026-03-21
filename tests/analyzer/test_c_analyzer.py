import pytest
from pathlib import Path
from sepgen.analyzer.c_analyzer import CAnalyzer
from sepgen.models.access import AccessType

def test_analyze_fopen_call():
    """Test analyzing fopen() call"""
    analyzer = CAnalyzer()
    code = '''
    int main() {
        FILE *f = fopen("/etc/myapp.conf", "r");
        fclose(f);
        return 0;
    }
    '''

    accesses = analyzer.analyze_string(code)
    file_reads = [a for a in accesses if a.access_type == AccessType.FILE_READ]

    assert len(file_reads) >= 1
    assert any(a.path == "/etc/myapp.conf" for a in file_reads)

def test_analyze_socket_call():
    """Test analyzing socket() call"""
    analyzer = CAnalyzer()
    code = '''
    int main() {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        return 0;
    }
    '''

    accesses = analyzer.analyze_string(code)
    socket_creates = [a for a in accesses if a.access_type == AccessType.SOCKET_CREATE]

    assert len(socket_creates) >= 1

def test_analyze_file():
    """Test analyzing complete C file"""
    analyzer = CAnalyzer()
    fixture = Path(__file__).parent.parent / "fixtures" / "sample_c_program.c"

    accesses = analyzer.analyze_file(fixture)

    # Should find fopen calls
    file_accesses = [a for a in accesses if a.access_type in [AccessType.FILE_READ, AccessType.FILE_WRITE]]
    assert len(file_accesses) >= 2

    # Should find socket call
    socket_accesses = [a for a in accesses if a.access_type == AccessType.SOCKET_CREATE]
    assert len(socket_accesses) >= 1
