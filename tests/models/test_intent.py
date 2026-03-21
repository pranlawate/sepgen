import pytest
from sepgen.models.intent import Intent, IntentType
from sepgen.models.access import Access, AccessType

def test_create_intent():
    """Test creating an intent"""
    access = Access(
        access_type=AccessType.FILE_READ,
        path="/etc/app.conf",
        syscall="open"
    )
    intent = Intent(
        intent_type=IntentType.CONFIG_FILE,
        accesses=[access],
        confidence=0.95
    )
    assert intent.intent_type == IntentType.CONFIG_FILE
    assert len(intent.accesses) == 1
    assert intent.confidence == 0.95

def test_intent_with_selinux_type():
    """Test intent with SELinux type assigned"""
    access = Access(
        access_type=AccessType.FILE_WRITE,
        path="/var/run/app.pid",
        syscall="open"
    )
    intent = Intent(
        intent_type=IntentType.PID_FILE,
        accesses=[access],
        selinux_type="myapp_var_run_t"
    )
    assert intent.selinux_type == "myapp_var_run_t"
