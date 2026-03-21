from pathlib import Path
from sepgen.models.policy import PolicyModule


class TEWriter:
    """Serialize PolicyModule to .te file format"""

    def write(self, policy: PolicyModule, output_path: Path) -> None:
        lines = []

        lines.append(f"policy_module({policy.name}, {policy.version})")
        lines.append("")

        if policy.require:
            lines.append(str(policy.require))
            lines.append("")

        lines.append("########################################")
        lines.append("# Declarations")
        lines.append("########################################")
        lines.append("")

        for type_decl in policy.types:
            lines.append(str(type_decl))

        for ta in policy.typeattributes:
            lines.append(str(ta))

        lines.append("")

        lines.append("########################################")
        lines.append("# Policy")
        lines.append("########################################")
        lines.append("")

        for macro in policy.macro_calls:
            lines.append(str(macro))

        for rule in policy.allow_rules:
            lines.append(str(rule))

        output_path.write_text("\n".join(lines) + "\n")
