"""Run strace and capture output for policy generation."""
import os
import shutil
import signal
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, List


class ProcessTracer:
    """Execute and trace processes with strace.

    Uses strace flags from best practices:
    --secontext: Show SELinux contexts on files and processes
    -f: Follow forks (essential for multi-process daemons)
    -tt: Microsecond timestamps
    -T: Per-syscall duration
    -v: Verbose struct decoding
    -yy: Decode FD paths and socket addresses
    -s 256: Capture up to 256 bytes of string arguments
    """

    STRACE_ARGS = [
        '--secontext',
        '-f', '-tt', '-T', '-v', '-yy',
        '-s', '256',
        '-e', 'trace=file,network,ipc,process',
    ]

    def build_strace_command(
        self,
        binary: Optional[str] = None,
        args: str = '',
        pid: Optional[int] = None,
        output_file: Optional[str] = None,
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

    def check_secontext(self) -> bool:
        """Check if strace supports --secontext."""
        try:
            result = subprocess.run(
                ['strace', '--secontext', '-e', 'trace=none', '/bin/true'],
                capture_output=True, timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def trace(
        self,
        binary: Optional[str] = None,
        args: str = '',
        pid: Optional[int] = None,
        output_file: Optional[Path] = None,
        duration: Optional[int] = None,
    ) -> Path:
        """Trace a process and return path to strace output.

        For daemons, use duration to trace for N seconds then stop.
        For short-lived commands, strace stops when the command exits.
        """
        if not self.check_strace():
            raise RuntimeError("strace not found. Install with: sudo dnf install strace")

        if not self.check_secontext():
            self.STRACE_ARGS = [a for a in self.STRACE_ARGS if a != '--secontext']

        if output_file is None:
            fd, temp_path = tempfile.mkstemp(suffix='.strace', prefix='sepgen-')
            os.close(fd)
            output_file = Path(temp_path)

        cmd = self.build_strace_command(binary, args, pid, str(output_file))

        try:
            if duration:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    proc.wait(timeout=duration)
                except subprocess.TimeoutExpired:
                    proc.send_signal(signal.SIGINT)
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
            else:
                subprocess.run(cmd, check=False, capture_output=True)
        except PermissionError:
            raise RuntimeError(
                "Permission denied tracing process. Try: sudo sepgen trace ..."
            )
        except FileNotFoundError:
            raise RuntimeError("strace not found. Install with: sudo dnf install strace")

        if not output_file.exists() or output_file.stat().st_size == 0:
            raise RuntimeError(
                "strace produced no output. Check that the binary exists and you have permissions."
            )

        return output_file

    def trace_service(
        self,
        service_name: str,
        output_file: Optional[Path] = None,
        duration: int = 10,
    ) -> Path:
        """Trace a systemd service by attaching to PID 1, starting the service,
        then extracting the relevant PIDs.

        This captures the full daemon lifecycle including systemd setup.
        """
        if output_file is None:
            fd, temp_path = tempfile.mkstemp(suffix='.strace', prefix='sepgen-')
            os.close(fd)
            output_file = Path(temp_path)

        cmd = self.build_strace_command(pid=1, output_file=str(output_file))

        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        import time
        time.sleep(1)

        subprocess.run(['systemctl', 'start', service_name], capture_output=True)
        time.sleep(duration)
        subprocess.run(['systemctl', 'stop', service_name], capture_output=True)

        time.sleep(1)
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

        return output_file
