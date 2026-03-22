"""Run strace and capture output for policy generation."""
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, List


class ProcessTracer:
    """Execute and trace processes with strace."""

    STRACE_ARGS = ['-f', '-e', 'trace=file,network,ipc,process']

    def build_strace_command(
        self,
        binary: Optional[str] = None,
        args: str = '',
        pid: Optional[int] = None,
        output_file: Optional[str] = None,
        duration: Optional[int] = None,
    ) -> List[str]:
        """Build strace command line."""
        cmd = ['strace'] + self.STRACE_ARGS

        if output_file:
            cmd.extend(['-o', output_file])

        if pid:
            cmd.extend(['-p', str(pid)])
        elif binary:
            cmd.append(binary)
            if args:
                cmd.extend(args.split())
        else:
            raise ValueError("Either binary or pid must be provided")

        return cmd

    def check_strace(self) -> bool:
        """Check if strace is available."""
        return shutil.which('strace') is not None

    def trace(
        self,
        binary: Optional[str] = None,
        args: str = '',
        pid: Optional[int] = None,
        output_file: Optional[Path] = None,
        duration: Optional[int] = None,
    ) -> Path:
        """Trace a process and return path to strace output."""
        if not self.check_strace():
            raise RuntimeError("strace not found. Install with: sudo dnf install strace")

        if output_file is None:
            fd, temp_path = tempfile.mkstemp(suffix='.strace', prefix='sepgen-')
            output_file = Path(temp_path)

        cmd = self.build_strace_command(binary, args, pid, str(output_file), duration)

        try:
            if duration and pid:
                subprocess.run(cmd, check=False, capture_output=True, timeout=duration)
            else:
                subprocess.run(cmd, check=False, capture_output=True)
        except subprocess.TimeoutExpired:
            pass
        except PermissionError:
            raise RuntimeError(
                f"Permission denied tracing process. Try: sudo sepgen trace ..."
            )
        except FileNotFoundError:
            raise RuntimeError("strace not found. Install with: sudo dnf install strace")

        if not output_file.exists() or output_file.stat().st_size == 0:
            raise RuntimeError(
                f"strace produced no output. Check that the binary exists and you have permissions."
            )

        return output_file
