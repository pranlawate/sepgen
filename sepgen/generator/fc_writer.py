from pathlib import Path
from sepgen.models.policy import FileContexts


class FCWriter:
    """Serialize FileContexts to .fc file format"""

    def write(self, contexts: FileContexts, output_path: Path) -> None:
        lines = []

        for entry in sorted(contexts.entries, key=lambda e: e.path):
            lines.append(str(entry))

        output_path.write_text("\n".join(lines) + "\n")
