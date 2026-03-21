from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class TypeDeclaration:
    """SELinux type declaration"""
    name: str
    attributes: List[str] = field(default_factory=list)

    def __str__(self):
        return f"type {self.name};"

@dataclass
class AllowRule:
    """SELinux allow rule"""
    source: str
    target: str
    object_class: str
    permissions: List[str]

    def __str__(self):
        perms = " ".join(self.permissions)
        return f"allow {self.source} {self.target}:{self.object_class} {{ {perms} }};"

@dataclass
class MacroCall:
    """Policy macro invocation"""
    name: str
    args: List[str]

    def __str__(self):
        args_str = ", ".join(self.args)
        return f"{self.name}({args_str})"

@dataclass
class TypeAttribute:
    """typeattribute statement: typeattribute type_name attribute;"""
    type_name: str
    attribute: str

    def __str__(self):
        return f"typeattribute {self.type_name} {self.attribute};"


@dataclass
class RequireBlock:
    """require block for referencing external attributes/types."""
    attributes: List[str] = field(default_factory=list)

    def __str__(self):
        lines = ["require {"]
        for attr in self.attributes:
            lines.append(f"\tattribute {attr};")
        lines.append("}")
        return "\n".join(lines)


@dataclass
class PolicyModule:
    """Structured representation of .te policy file"""
    name: str
    version: str
    types: List[TypeDeclaration] = field(default_factory=list)
    allow_rules: List[AllowRule] = field(default_factory=list)
    macro_calls: List[MacroCall] = field(default_factory=list)
    typeattributes: List[TypeAttribute] = field(default_factory=list)
    require: Optional['RequireBlock'] = None

    def add_type(self, type_name: str, attributes: List[str] = None):
        """Add a type declaration (deduplicated by name)."""
        if any(t.name == type_name for t in self.types):
            return
        self.types.append(TypeDeclaration(type_name, attributes or []))

    def add_macro(self, macro_name: str, args: List[str]):
        """Add a macro call (deduplicated by name+args)."""
        if any(m.name == macro_name and m.args == args for m in self.macro_calls):
            return
        self.macro_calls.append(MacroCall(macro_name, args))

@dataclass
class FileContextEntry:
    """Single file context entry"""
    path: str
    selinux_type: str
    file_type: str = "all_files"

    def __str__(self):
        return f"{self.path}\t\tgen_context(system_u:object_r:{self.selinux_type},s0)"

@dataclass
class FileContexts:
    """Structured representation of .fc file"""
    entries: List[FileContextEntry] = field(default_factory=list)

    def add_entry(self, path: str, selinux_type: str):
        """Add a file context entry"""
        self.entries.append(FileContextEntry(path, selinux_type))
