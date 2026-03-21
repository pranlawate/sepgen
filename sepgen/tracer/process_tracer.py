import subprocess
import tempfile
from pathlib import Path
from typing import Optional, List


class ProcessTracer:
    """Execute and trace processes with strace"""

    def build_strace_command(
        self,
        binary: Optional[str] = None,
        args: str = '',
        pid: Optional[int] = None,
        output_file: Optional[str] = None
    ) -> List[str]:
        """Build strace command line"""
        cmd = ['strace', '-f', '-e', 'trace=file,network,ipc']

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

    def trace(
        self,
        binary: Optional[str] = None,
        args: str = '',
        pid: Optional[int] = None,
        output_file: Optional[Path] = None
    ) -> Path:
        """Trace a process and return path to strace output"""
        if output_file is None:
            fd, temp_path = tempfile.mkstemp(suffix='.strace', prefix='sepgen-')
            output_file = Path(temp_path)

        cmd = self.build_strace_command(binary, args, pid, str(output_file))

        try:
            subprocess.run(cmd, check=True, capture_output=True)
        except subprocess.CalledProcessError:
            pass

        return output_file
