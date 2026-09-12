#!/usr/bin/env python3

from pwn import *

exe = ELF("./pkm_nopie_patched_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

# split tmux pane
context.terminal = ["tmux", "splitw", "-vf","-p", "70"]
# spawn new window
# context.terminal = ["tmux", "neww", "-n", "shell"]

context.log_level = "debug"
elf.binsh = next(libc.search(b"/bin/sh\0"))
DOCKER_PORT		= 1337
REMOTE_NC_CMD	= "nc "	# `nc <host> <port>`

bstr = lambda x: str(x).encode()
ELF.binsh = lambda self: next(self.search(b"/bin/sh\0"))
chunks = lambda data: [data[i:i+context.bytes] for i in range(0, len(data), context.bytes)]
aleak = lambda elfname, addr: log.info(elfname + " @ 0x" + format(addr, 'x'))
vleak = lambda valname, val: log.info(valname + " @ 0x" + format(val, 'x'))
GDB_SCRIPT = """

"""

if args.GDB:
    r = gdb.debug(elf.path,gdbscript=GDB_SCRIPT)
elif args.LOCAL:
    r = process(elf.path)
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




def main():


    

    r.interactive()


if __name__ == "__main__":
    main()
