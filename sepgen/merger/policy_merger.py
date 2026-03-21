import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Tuple, Optional, List
from sepgen.models.policy import PolicyModule, TypeDeclaration, MacroCall


@dataclass
class MergeReport:
    """Report of policy comparison"""
    matched_types: List[TypeDeclaration] = field(default_factory=list)
    new_types: List[TypeDeclaration] = field(default_factory=list)
    existing_only_types: List[TypeDeclaration] = field(default_factory=list)
    matched_macros: List[MacroCall] = field(default_factory=list)
    new_macros: List[MacroCall] = field(default_factory=list)
    conflicts: List[dict] = field(default_factory=list)


class PolicyMerger:
    """Handle policy comparison and merging"""

    def detect_existing_policy(self, module_name: str) -> Tuple[Optional[Path], Optional[Path]]:
        te_path = Path(f"{module_name}.te").resolve()
        fc_path = Path(f"{module_name}.fc").resolve()

        return (
            te_path if te_path.exists() else None,
            fc_path if fc_path.exists() else None
        )

    def load_existing_policy(self, te_path: Path) -> PolicyModule:
        """Parse existing .te file with basic regex parsing"""
        content = te_path.read_text()

        module_match = re.search(r'policy_module\((\w+),\s*([\d.]+)\)', content)
        if module_match:
            name = module_match.group(1)
            version = module_match.group(2)
        else:
            name = "unknown"
            version = "1.0.0"

        policy = PolicyModule(name=name, version=version)

        for match in re.finditer(r'type (\w+);', content):
            policy.types.append(TypeDeclaration(match.group(1)))

        for match in re.finditer(r'(\w+)\(([^)]+)\)', content):
            macro_name = match.group(1)
            args = [arg.strip() for arg in match.group(2).split(',')]
            policy.macro_calls.append(MacroCall(macro_name, args))

        return policy

    def compare(self, existing: PolicyModule, new: PolicyModule) -> MergeReport:
        """Compare two policies and identify differences"""
        report = MergeReport()

        existing_type_names = {t.name for t in existing.types}
        new_type_names = {t.name for t in new.types}

        matched = existing_type_names & new_type_names
        report.matched_types = [t for t in new.types if t.name in matched]
        report.new_types = [t for t in new.types if t.name not in existing_type_names]
        report.existing_only_types = [t for t in existing.types if t.name not in new_type_names]

        existing_macros = {(m.name, tuple(m.args)): m for m in existing.macro_calls}
        new_macros = {(m.name, tuple(m.args)): m for m in new.macro_calls}

        conflict_new_keys = set()
        for new_key, new_macro in new_macros.items():
            for existing_key, existing_macro in existing_macros.items():
                if existing_key == new_key:
                    continue
                same_name_diff_args = existing_key[0] == new_key[0] and existing_key[1] != new_key[1]
                diff_name_same_args = existing_key[0] != new_key[0] and existing_key[1] == new_key[1]
                if same_name_diff_args or diff_name_same_args:
                    report.conflicts.append({
                        'type': 'macro',
                        'name': new_macro.name,
                        'existing': existing_macro,
                        'new': new_macro
                    })
                    conflict_new_keys.add(new_key)
                    break

        matched_macro_keys = set(existing_macros.keys()) & set(new_macros.keys())
        report.matched_macros = [new_macros[k] for k in matched_macro_keys]

        new_macro_keys = set(new_macros.keys()) - set(existing_macros.keys()) - conflict_new_keys
        report.new_macros = [new_macros[k] for k in new_macro_keys]

        return report

    def merge(
        self,
        existing: PolicyModule,
        new: PolicyModule,
        strategy: str = "trace-wins",
        auto_approve: bool = False
    ) -> PolicyModule:
        """Merge policies according to strategy"""
        report = self.compare(existing, new)

        merged = PolicyModule(name=existing.name, version=existing.version)
        merged.types = existing.types.copy()
        merged.macro_calls = existing.macro_calls.copy()
        merged.allow_rules = existing.allow_rules.copy()

        for new_type in report.new_types:
            merged.types.append(new_type)

        if strategy == "trace-wins":
            if auto_approve or not report.conflicts:
                for conflict in report.conflicts:
                    merged.macro_calls = [
                        m for m in merged.macro_calls
                        if not (m.name == conflict['existing'].name)
                    ]
                    merged.macro_calls.append(conflict['new'])

        for new_macro in report.new_macros:
            merged.macro_calls.append(new_macro)

        return merged
