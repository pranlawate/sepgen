from typing import List, Optional
from sepgen.models.access import Access, AccessType


class SyscallMapper:
    """Map C library function calls to syscalls"""

    # Direct function → syscall mappings
    FUNCTION_TO_SYSCALL = {
        'fopen': 'open',
        'open': 'open',
        'creat': 'creat',
        'socket': 'socket',
        'bind': 'bind',
        'listen': 'listen',
        'connect': 'connect',
        'accept': 'accept',
    }

    def map_function_call(self, func_name: str, args: List[str]) -> Optional[Access]:
        """Map a function call to a system access"""
        if func_name in ['fopen', 'open']:
            return self._map_open_call(func_name, args)
        elif func_name == 'socket':
            return self._map_socket_call(args)
        elif func_name == 'bind':
            return self._map_bind_call(args)

        return None

    def _map_open_call(self, func_name: str, args: List[str]) -> Optional[Access]:
        """Map fopen/open to file access"""
        if not args:
            return None

        # Extract path (remove quotes)
        path = args[0].strip('"')

        # Determine access type from mode
        mode = args[1].strip('"') if len(args) > 1 else 'r'

        if func_name == 'fopen':
            # fopen modes: r, w, a, r+, w+, a+
            if 'w' in mode or 'a' in mode:
                access_type = AccessType.FILE_WRITE
            else:
                access_type = AccessType.FILE_READ
        else:
            # open() flags - default to read
            access_type = AccessType.FILE_READ

        return Access(
            access_type=access_type,
            path=path,
            syscall=self.FUNCTION_TO_SYSCALL[func_name],
            details={"mode": mode}
        )

    def _map_socket_call(self, args: List[str]) -> Access:
        """Map socket() call"""
        domain = args[0] if args else 'AF_INET'
        sock_type = args[1] if len(args) > 1 else 'SOCK_STREAM'

        return Access(
            access_type=AccessType.SOCKET_CREATE,
            path=f"{domain}:{sock_type}",
            syscall="socket",
            details={"domain": domain, "type": sock_type}
        )

    def _map_bind_call(self, args: List[str]) -> Access:
        """Map bind() call - basic placeholder"""
        return Access(
            access_type=AccessType.SOCKET_BIND,
            path="tcp:unknown",
            syscall="bind",
            details={"port": None}
        )
