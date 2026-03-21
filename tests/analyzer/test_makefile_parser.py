from sepgen.analyzer.makefile_parser import MakefileParser


def test_parse_testprog_makefile(tmp_path):
    """testprog: PREFIX=/usr, cp to $(PREFIX)/bin"""
    (tmp_path / "Makefile").write_text("""
CC=gcc
PREFIX = /usr

testprog: testprog.c
\t$(CC) -o testprog testprog.c

install:
\tmkdir -p $(DESTDIR)$(PREFIX)/bin
\tcp testprog $(DESTDIR)$(PREFIX)/bin/testprog
""")
    parser = MakefileParser()
    info = parser.parse(tmp_path)
    assert info.prog_name == "testprog"
    assert info.exec_path == "/usr/bin/testprog"


def test_parse_mcstrans_makefile(tmp_path):
    """mcstransd: SBINDIR=/sbin, PROG=mcstransd, install to $(SBINDIR)"""
    (tmp_path / "Makefile").write_text("""
PREFIX ?= /usr
SBINDIR ?= /sbin

PROG=mcstransd
INITSCRIPT=mcstrans

install: all
\tinstall -m 755 $(PROG) $(DESTDIR)$(SBINDIR)
""")
    parser = MakefileParser()
    info = parser.parse(tmp_path)
    assert info.prog_name == "mcstransd"
    assert info.uses_sbin is True
    assert info.exec_path == "/sbin/mcstransd"
    assert info.init_script == "mcstrans"


def test_parse_no_makefile(tmp_path):
    parser = MakefileParser()
    info = parser.parse(tmp_path)
    assert info.prog_name is None
    assert info.exec_path is None


def test_parse_searches_parent(tmp_path):
    """Makefile in parent dir should be found when scanning src/."""
    subdir = tmp_path / "src"
    subdir.mkdir()
    (tmp_path / "Makefile").write_text("PROG=myapp\nSBINDIR ?= /usr/sbin\n")
    parser = MakefileParser()
    info = parser.parse(subdir)
    assert info.prog_name == "myapp"
