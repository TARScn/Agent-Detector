"""Static syscall-number tables for the syscalls the audit rules watch.

auditd logs SYSCALL records with a numeric ``syscall=`` field plus an ``arch=``
machine token, so classification needs a number→name mapping. Unknown numbers
degrade to key/nametype-based classification (see normalizer).
"""

X86_64 = {
    2: "open", 42: "connect", 56: "clone", 57: "fork", 58: "vfork", 59: "execve",
    62: "kill", 76: "truncate", 77: "ftruncate", 82: "rename", 83: "mkdir",
    84: "rmdir", 85: "creat", 86: "link", 87: "unlink", 88: "symlink",
    90: "chmod", 91: "fchmod", 92: "chown", 93: "fchown", 94: "lchown",
    165: "mount", 166: "umount2", 188: "setxattr", 189: "lsetxattr",
    190: "fsetxattr", 197: "removexattr", 198: "lremovexattr",
    199: "fremovexattr", 200: "tkill", 234: "tgkill", 257: "openat",
    258: "mkdirat", 260: "fchownat", 263: "unlinkat", 264: "renameat",
    265: "linkat", 266: "symlinkat", 268: "fchmodat", 316: "renameat2",
    322: "execveat", 437: "openat2",
}

AARCH64 = {  # asm-generic ABI (arm64 has no non-*at file syscalls)
    5: "setxattr", 6: "lsetxattr", 7: "fsetxattr", 14: "removexattr",
    15: "lremovexattr", 16: "fremovexattr", 34: "mkdirat", 35: "unlinkat",
    36: "symlinkat", 37: "linkat", 38: "renameat", 39: "umount2", 40: "mount",
    45: "truncate", 46: "ftruncate", 52: "fchmod", 53: "fchmodat",
    54: "fchownat", 55: "fchown", 56: "openat", 129: "kill", 130: "tkill",
    131: "tgkill", 203: "connect", 220: "clone", 221: "execve",
    276: "renameat2", 281: "execveat", 437: "openat2",
}

I386 = {  # 32-bit x86 (best effort; connect goes through socketcall)
    9: "link", 10: "unlink", 11: "execve", 15: "chmod", 16: "lchown",
    21: "mount", 22: "umount2", 37: "kill", 38: "rename", 39: "mkdir",
    40: "rmdir", 83: "symlink", 90: "chown", 94: "fchown", 95: "fchmod",
    102: "socketcall", 197: "removexattr", 198: "lremovexattr",
    199: "fremovexattr", 226: "setxattr", 227: "lsetxattr", 228: "fsetxattr",
    295: "openat", 296: "mkdirat", 298: "fchownat", 301: "unlinkat",
    302: "renameat", 303: "linkat", 304: "symlinkat", 306: "fchmodat",
    353: "renameat2", 358: "execveat", 437: "openat2",
}

_ARCHES = {"c000003e": X86_64, "c00000b7": AARCH64, "40000003": I386}

EXEC_SYSCALLS = frozenset({"execve", "execveat"})
WRITE_SYSCALLS = frozenset({"open", "openat", "openat2", "creat", "truncate",
                            "ftruncate", "write", "mkdir", "mkdirat", "symlink",
                            "symlinkat", "link", "linkat"})
ATTR_SYSCALLS = frozenset({"chmod", "fchmod", "fchmodat", "chown", "fchown",
                           "lchown", "fchownat", "setxattr", "lsetxattr",
                           "fsetxattr", "removexattr", "lremovexattr",
                           "fremovexattr"})
MOVE_SYSCALLS = frozenset({"rename", "renameat", "renameat2"})
DELETE_SYSCALLS = frozenset({"unlink", "unlinkat", "rmdir"})
READ_SYSCALLS = frozenset({"open", "openat", "openat2"})
NET_SYSCALLS = frozenset({"connect", "socketcall"})
KILL_SYSCALLS = frozenset({"kill", "tkill", "tgkill"})


def syscall_name(arch: str | None, number: int | None) -> str | None:
    if not arch or number is None:
        return None
    table = _ARCHES.get(str(arch).lower().strip())
    return table.get(number) if table else None