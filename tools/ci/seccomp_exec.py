"""Test helper: install a seccomp filter that answers the given syscall numbers with EPERM, then exec.

Usage: seccomp_exec.py NR[,NR...] PROGRAM [ARG...]

The Go test of the tick tripwire (internal/rangerun/filter_test.go) runs its child under this, as the tick unit's filter
would: Go code may not use unsafe (ENGINEERING.md 7), and the kernel takes the filter by pointer. The
process is single-threaded here, so the filter set before exec covers every thread the program starts.
x86-64 only; no architecture check, which a test filter does not need.
"""

import ctypes
import os
import struct
import sys

PR_SET_NO_NEW_PRIVS = 38
SYS_SECCOMP = 317
SECCOMP_SET_MODE_FILTER = 1
EPERM = 1
LD_ABS_W, JEQ_K, RET_K = 0x20, 0x15, 0x06
RET_ALLOW, RET_ERRNO = 0x7FFF0000, 0x00050000


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def program(nrs: list[int]) -> bytes:
    ins = [(LD_ABS_W, 0, 0, 0)]  # A = seccomp_data.nr
    for nr in nrs:
        ins += [(JEQ_K, 0, 1, nr), (RET_K, 0, 0, RET_ERRNO | EPERM)]
    ins.append((RET_K, 0, 0, RET_ALLOW))
    return b"".join(struct.pack("<HBBI", *i) for i in ins)


def main() -> None:
    nrs = [int(n) for n in sys.argv[1].split(",") if n]
    prog = program(nrs)
    buf = ctypes.create_string_buffer(prog, len(prog))
    fprog = SockFprog(len(prog) // 8, ctypes.cast(buf, ctypes.c_void_p))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        sys.exit(f"prctl: errno {ctypes.get_errno()}")
    if libc.syscall(SYS_SECCOMP, SECCOMP_SET_MODE_FILTER, 0, ctypes.byref(fprog)) != 0:
        sys.exit(f"seccomp: errno {ctypes.get_errno()}")
    os.execv(sys.argv[2], sys.argv[2:])


if __name__ == "__main__":
    main()
