from pathlib import Path
from sepgen.analyzer.service_detector import ServiceDetector


def test_detect_service_file(tmp_path):
    (tmp_path / "myapp.service").write_text(
        "[Service]\nExecStart=/usr/bin/myapp --daemon\n"
    )
    detector = ServiceDetector()
    info = detector.detect_service_files(tmp_path)

    assert info.has_service_file
    assert info.exec_path == "/usr/bin/myapp"


def test_detect_init_script(tmp_path):
    (tmp_path / "myapp.init").write_text("#!/bin/bash\n")
    detector = ServiceDetector()
    info = detector.detect_service_files(tmp_path)

    assert info.has_init_script
    assert info.needs_initrc_exec_t


def test_no_service_files(tmp_path):
    (tmp_path / "main.c").write_text("int main() {}")
    detector = ServiceDetector()
    info = detector.detect_service_files(tmp_path)

    assert not info.has_service_file
    assert not info.has_init_script
    assert info.exec_path is None


def test_initrc_type_generation(tmp_path):
    (tmp_path / "myapp.init").write_text("#!/bin/bash\n")
    detector = ServiceDetector()
    info = detector.detect_service_files(tmp_path)

    from sepgen.generator.te_generator import TEGenerator
    policy = TEGenerator("myapp").generate([], service_info=info)

    type_names = [t.name for t in policy.types]
    assert "myapp_initrc_exec_t" in type_names

    macro_names = [m.name for m in policy.macro_calls]
    assert "init_script_file" in macro_names
